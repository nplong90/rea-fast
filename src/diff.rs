use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityDiff {
    pub id: String,
    pub path: String,
    pub kind: String,
    pub changes: Vec<FieldDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDiff {
    pub pointer: String,
    pub status: String,
    pub left: Option<Value>,
    pub right: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApplicationGraphDiff {
    pub added_modules: Vec<String>,
    pub removed_modules: Vec<String>,
    pub changed_modules: Vec<EntityDiff>,
    pub unchanged_modules: Vec<String>,
    pub added_edges: Vec<String>,
    pub removed_edges: Vec<String>,
    pub ambiguous: Vec<String>,
    pub unknown: Vec<String>,
    pub changed_from: HashMap<String, String>,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiffSummary {
    pub added_count: usize,
    pub removed_count: usize,
    pub changed_count: usize,
    pub unchanged_count: usize,
    pub edge_added_count: usize,
    pub edge_removed_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportShapeDiff {
    pub left_module: String,
    pub left_export: String,
    pub right_module: String,
    pub right_export: String,
    pub status: String,
    pub differences: Vec<FieldDiff>,
    pub shape_compatible: bool,
    pub limitations: Vec<String>,
}

pub struct ApplicationDiffer;

impl ApplicationDiffer {
    fn extract_graph_payload(val: &Value) -> Option<&Value> {
        if val.get("nodes").or_else(|| val.get("modules")).is_some() {
            Some(val)
        } else if let Some(norm) = val.get("normalized_result") {
            Self::extract_graph_payload(norm)
        } else if let Some(raw) = val.get("raw_result") {
            Self::extract_graph_payload(raw)
        } else {
            None
        }
    }

    fn validated_nodes<'a>(graph: &'a Value, side: &str) -> Result<&'a [Value], String> {
        let nodes = graph
            .get("nodes")
            .or_else(|| graph.get("modules"))
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{side} graph nodes/modules must be an array"))?;
        let mut paths = HashSet::new();
        for (index, node) in nodes.iter().enumerate() {
            let path = node
                .pointer("/identity/path")
                .or_else(|| node.get("path"))
                .and_then(Value::as_str)
                .filter(|p| !p.trim().is_empty())
                .ok_or_else(|| format!("{side} node {index} lacks a non-empty path"))?;
            if !paths.insert(path) {
                return Err(format!("{side} graph has duplicate module path: {path}"));
            }
        }
        Ok(nodes)
    }

    pub fn compare_applications(
        left_val: &Value,
        right_val: &Value,
    ) -> Result<ApplicationGraphDiff, String> {
        let left_graph = Self::extract_graph_payload(left_val)
            .ok_or_else(|| "Left input contains no valid application graph payload".to_string())?;
        let right_graph = Self::extract_graph_payload(right_val)
            .ok_or_else(|| "Right input contains no valid application graph payload".to_string())?;

        let left_nodes = Self::validated_nodes(left_graph, "Left")?;
        let right_nodes = Self::validated_nodes(right_graph, "Right")?;

        let mut left_by_path: HashMap<String, &Value> = HashMap::new();
        let mut left_by_sha: HashMap<String, Vec<String>> = HashMap::new();
        for node in left_nodes {
            if let Some(path) = node
                .pointer("/identity/path")
                .or_else(|| node.get("path"))
                .and_then(|p| p.as_str())
            {
                left_by_path.insert(path.to_string(), node);
            }
            if let Some(sha) = node
                .pointer("/identity/artifact_sha256")
                .or_else(|| node.get("sha256"))
                .or_else(|| node.get("artifact_sha256"))
                .and_then(|s| s.as_str())
                && let Some(path) = node
                    .pointer("/identity/path")
                    .or_else(|| node.get("path"))
                    .and_then(|p| p.as_str())
            {
                left_by_sha
                    .entry(sha.to_string())
                    .or_default()
                    .push(path.to_string());
            }
        }

        let mut right_by_path: HashMap<String, &Value> = HashMap::new();
        for node in right_nodes {
            if let Some(path) = node
                .pointer("/identity/path")
                .or_else(|| node.get("path"))
                .and_then(|p| p.as_str())
            {
                right_by_path.insert(path.to_string(), node);
            }
        }

        let mut added_modules = Vec::new();
        let mut removed_modules = Vec::new();
        let mut changed_modules = Vec::new();
        let mut unchanged_modules = Vec::new();
        let mut changed_from = HashMap::new();
        let mut ambiguous = Vec::new();

        // 1. Process right nodes against left
        for (r_path, r_node) in &right_by_path {
            let r_sha = r_node
                .pointer("/identity/artifact_sha256")
                .and_then(|s| s.as_str());

            if let Some(l_node) = left_by_path.get(r_path) {
                let l_sha = l_node
                    .pointer("/identity/artifact_sha256")
                    .and_then(|s| s.as_str());

                if l_sha.is_some() && l_sha == r_sha {
                    unchanged_modules.push(r_path.clone());
                } else {
                    let mut changes = Vec::new();
                    // Diff sha
                    changes.push(FieldDiff {
                        pointer: "/identity/artifact_sha256".to_string(),
                        status: "changed".to_string(),
                        left: l_sha.map(|s| json!(s)),
                        right: r_sha.map(|s| json!(s)),
                    });

                    // Compare properties / AST facts
                    Self::diff_module_properties(l_node, r_node, &mut changes);

                    let entity_diff = EntityDiff {
                        id: r_node
                            .get("node_id")
                            .and_then(|id| id.as_str())
                            .unwrap_or(r_path)
                            .to_string(),
                        path: r_path.clone(),
                        kind: "source-module".to_string(),
                        changes,
                    };
                    changed_modules.push(entity_diff);
                    changed_from.insert(r_path.clone(), r_path.clone());
                }
            } else {
                // Not found by path. Check if it was renamed by matching exact artifact_sha256
                if let Some(sha) = r_sha
                    && let Some(matching_left_paths) = left_by_sha.get(sha)
                {
                    if matching_left_paths.len() == 1 {
                        let old_path = &matching_left_paths[0];
                        changed_from.insert(r_path.clone(), old_path.clone());
                        changed_modules.push(EntityDiff {
                            id: r_node
                                .get("node_id")
                                .and_then(|id| id.as_str())
                                .unwrap_or(r_path)
                                .to_string(),
                            path: r_path.clone(),
                            kind: "source-module-renamed".to_string(),
                            changes: vec![FieldDiff {
                                pointer: "/identity/path".to_string(),
                                status: "renamed".to_string(),
                                left: Some(json!(old_path)),
                                right: Some(json!(r_path)),
                            }],
                        });
                        continue;
                    } else if matching_left_paths.len() > 1 {
                        ambiguous.push(format!("Multiple candidates for renamed module: {r_path}"));
                    }
                }
                added_modules.push(r_path.clone());
            }
        }

        // 2. Detect removed modules
        for l_path in left_by_path.keys() {
            if !right_by_path.contains_key(l_path) && !changed_from.values().any(|v| v == l_path) {
                removed_modules.push(l_path.clone());
            }
        }

        added_modules.sort();
        removed_modules.sort();
        unchanged_modules.sort();
        changed_modules.sort_by(|a, b| a.path.cmp(&b.path));

        // 3. Diff edges
        let left_edges = left_graph
            .get("edges")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();
        let right_edges = right_graph
            .get("edges")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();

        let edge_key = |edge: &Value| -> String {
            let src = edge
                .get("source_node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tgt = edge
                .get("target_node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let rel = edge
                .get("relation")
                .and_then(|v| v.as_str())
                .unwrap_or("imports");
            format!("{src}->{tgt}:{rel}")
        };

        let left_edge_keys: HashSet<String> = left_edges.iter().map(edge_key).collect();
        let right_edge_keys: HashSet<String> = right_edges.iter().map(edge_key).collect();

        let mut added_edges: Vec<String> = right_edge_keys
            .difference(&left_edge_keys)
            .cloned()
            .collect();
        let mut removed_edges: Vec<String> = left_edge_keys
            .difference(&right_edge_keys)
            .cloned()
            .collect();
        added_edges.sort();
        removed_edges.sort();

        let summary = DiffSummary {
            added_count: added_modules.len(),
            removed_count: removed_modules.len(),
            changed_count: changed_modules.len(),
            unchanged_count: unchanged_modules.len(),
            edge_added_count: added_edges.len(),
            edge_removed_count: removed_edges.len(),
        };

        Ok(ApplicationGraphDiff {
            added_modules,
            removed_modules,
            changed_modules,
            unchanged_modules,
            added_edges,
            removed_edges,
            ambiguous,
            unknown: vec![],
            changed_from,
            summary,
        })
    }

    fn diff_module_properties(l_node: &Value, r_node: &Value, changes: &mut Vec<FieldDiff>) {
        let l_props = l_node
            .pointer("/observations/0/properties")
            .or_else(|| l_node.get("properties"))
            .or(Some(l_node));
        let r_props = r_node
            .pointer("/observations/0/properties")
            .or_else(|| r_node.get("properties"))
            .or(Some(r_node));

        if let (Some(lp), Some(rp)) = (l_props, r_props) {
            let extract_name = |val: &Value| -> Option<String> {
                val.get("name")
                    .and_then(|n| n.as_str())
                    .map(ToString::to_string)
                    .or_else(|| val.as_str().map(ToString::to_string))
            };

            // Exports diff
            let l_exports = lp
                .get("exports")
                .and_then(|e| e.as_array())
                .cloned()
                .unwrap_or_default();
            let r_exports = rp
                .get("exports")
                .and_then(|e| e.as_array())
                .cloned()
                .unwrap_or_default();

            let l_exp_names: HashSet<String> = l_exports.iter().filter_map(extract_name).collect();
            let r_exp_names: HashSet<String> = r_exports.iter().filter_map(extract_name).collect();

            for added in r_exp_names.difference(&l_exp_names) {
                changes.push(FieldDiff {
                    pointer: format!("/exports/{added}"),
                    status: "added".to_string(),
                    left: None,
                    right: Some(json!(added)),
                });
            }

            for removed in l_exp_names.difference(&r_exp_names) {
                changes.push(FieldDiff {
                    pointer: format!("/exports/{removed}"),
                    status: "removed".to_string(),
                    left: Some(json!(removed)),
                    right: None,
                });
            }

            // Functions diff
            let l_funcs = lp
                .get("functions")
                .and_then(|f| f.as_array())
                .cloned()
                .unwrap_or_default();
            let r_funcs = rp
                .get("functions")
                .and_then(|f| f.as_array())
                .cloned()
                .unwrap_or_default();

            let l_fn_names: HashSet<String> = l_funcs.iter().filter_map(extract_name).collect();
            let r_fn_names: HashSet<String> = r_funcs.iter().filter_map(extract_name).collect();

            for added in r_fn_names.difference(&l_fn_names) {
                changes.push(FieldDiff {
                    pointer: format!("/functions/{added}"),
                    status: "added".to_string(),
                    left: None,
                    right: Some(json!(added)),
                });
            }

            for removed in l_fn_names.difference(&r_fn_names) {
                changes.push(FieldDiff {
                    pointer: format!("/functions/{removed}"),
                    status: "removed".to_string(),
                    left: Some(json!(removed)),
                    right: None,
                });
            }
        }
    }

    pub fn compare_export_shapes(
        left_val: &Value,
        left_module: &str,
        left_export: &str,
        right_val: &Value,
        right_module: &str,
        right_export: &str,
    ) -> Result<ExportShapeDiff, String> {
        let left_graph = Self::extract_graph_payload(left_val)
            .ok_or_else(|| "Left input contains no valid application graph payload".to_string())?;
        let right_graph = Self::extract_graph_payload(right_val)
            .ok_or_else(|| "Right input contains no valid application graph payload".to_string())?;
        Self::validated_nodes(left_graph, "Left")?;
        Self::validated_nodes(right_graph, "Right")?;

        let find_export = |graph: &Value, mod_path: &str, exp_name: &str| -> Option<Value> {
            let nodes = graph
                .get("nodes")
                .or_else(|| graph.get("modules"))?
                .as_array()?;
            for node in nodes {
                let p = node
                    .pointer("/identity/path")
                    .or_else(|| node.get("path"))?
                    .as_str()?;
                if p == mod_path {
                    let exports = node
                        .pointer("/observations/0/properties/exports")
                        .or_else(|| node.pointer("/properties/exports"))
                        .or_else(|| node.get("exports"))?
                        .as_array()?;
                    for exp in exports {
                        if exp.get("name").and_then(|n| n.as_str()) == Some(exp_name)
                            || exp.as_str() == Some(exp_name)
                        {
                            return Some(if exp.is_object() {
                                exp.clone()
                            } else {
                                json!({"name": exp_name})
                            });
                        }
                    }
                }
            }
            None
        };

        let find_function = |graph: &Value, mod_path: &str, fn_name: &str| -> Option<Value> {
            let nodes = graph
                .get("nodes")
                .or_else(|| graph.get("modules"))?
                .as_array()?;
            for node in nodes {
                let p = node
                    .pointer("/identity/path")
                    .or_else(|| node.get("path"))?
                    .as_str()?;
                if p == mod_path {
                    let funcs = node
                        .pointer("/observations/0/properties/functions")
                        .or_else(|| node.pointer("/properties/functions"))
                        .or_else(|| node.get("functions"))?
                        .as_array()?;
                    for func in funcs {
                        if func.get("name").and_then(|n| n.as_str()) == Some(fn_name)
                            || func.as_str() == Some(fn_name)
                        {
                            return Some(if func.is_object() {
                                func.clone()
                            } else {
                                json!({"name": fn_name})
                            });
                        }
                    }
                }
            }
            None
        };

        let l_exp = find_export(left_graph, left_module, left_export);
        let r_exp = find_export(right_graph, right_module, right_export);

        let mut differences = Vec::new();

        match (&l_exp, &r_exp) {
            (None, None) => {
                return Err(format!(
                    "Neither left {left_module}:{left_export} nor right {right_module}:{right_export} found"
                ));
            }
            (Some(_), None) => {
                differences.push(FieldDiff {
                    pointer: format!("/{right_export}"),
                    status: "removed".to_string(),
                    left: l_exp,
                    right: None,
                });
                return Ok(ExportShapeDiff {
                    left_module: left_module.to_string(),
                    left_export: left_export.to_string(),
                    right_module: right_module.to_string(),
                    right_export: right_export.to_string(),
                    status: "removed".to_string(),
                    differences,
                    shape_compatible: false,
                    limitations: vec!["Export absent on right target".to_string()],
                });
            }
            (None, Some(_)) => {
                differences.push(FieldDiff {
                    pointer: format!("/{right_export}"),
                    status: "added".to_string(),
                    left: None,
                    right: r_exp,
                });
                return Ok(ExportShapeDiff {
                    left_module: left_module.to_string(),
                    left_export: left_export.to_string(),
                    right_module: right_module.to_string(),
                    right_export: right_export.to_string(),
                    status: "added".to_string(),
                    differences,
                    shape_compatible: false,
                    limitations: vec!["Export absent on left target".to_string()],
                });
            }
            (Some(l), Some(r)) => {
                // Compare export kinds
                let l_kind = l.get("kind").and_then(|k| k.as_str());
                let r_kind = r.get("kind").and_then(|k| k.as_str());
                if l_kind != r_kind {
                    differences.push(FieldDiff {
                        pointer: "/kind".to_string(),
                        status: "changed".to_string(),
                        left: l_kind.map(|s| json!(s)),
                        right: r_kind.map(|s| json!(s)),
                    });
                }

                // Compare type_only
                let l_type = l
                    .get("type_only")
                    .and_then(|t| t.as_bool())
                    .unwrap_or(false);
                let r_type = r
                    .get("type_only")
                    .and_then(|t| t.as_bool())
                    .unwrap_or(false);
                if l_type != r_type {
                    differences.push(FieldDiff {
                        pointer: "/type_only".to_string(),
                        status: "changed".to_string(),
                        left: Some(json!(l_type)),
                        right: Some(json!(r_type)),
                    });
                }

                // Check function signatures if the export is a function
                let l_fn = find_function(left_graph, left_module, left_export);
                let r_fn = find_function(right_graph, right_module, right_export);

                if let (Some(lf), Some(rf)) = (l_fn, r_fn) {
                    let l_params = lf.get("params").and_then(|p| p.as_u64()).unwrap_or(0);
                    let r_params = rf.get("params").and_then(|p| p.as_u64()).unwrap_or(0);
                    if l_params != r_params {
                        differences.push(FieldDiff {
                            pointer: "/params/count".to_string(),
                            status: "changed".to_string(),
                            left: Some(json!(l_params)),
                            right: Some(json!(r_params)),
                        });
                    }

                    let l_async = lf
                        .get("is_async")
                        .and_then(|a| a.as_bool())
                        .unwrap_or(false);
                    let r_async = rf
                        .get("is_async")
                        .and_then(|a| a.as_bool())
                        .unwrap_or(false);
                    if l_async != r_async {
                        differences.push(FieldDiff {
                            pointer: "/is_async".to_string(),
                            status: "changed".to_string(),
                            left: Some(json!(l_async)),
                            right: Some(json!(r_async)),
                        });
                    }
                }
            }
        }

        let is_compatible = differences.is_empty();
        let status = if is_compatible {
            "unchanged"
        } else {
            "changed"
        };

        Ok(ExportShapeDiff {
            left_module: left_module.to_string(),
            left_export: left_export.to_string(),
            right_module: right_module.to_string(),
            right_export: right_export.to_string(),
            status: status.to_string(),
            differences,
            shape_compatible: is_compatible,
            limitations: vec![
                "Static shape comparison based on AST syntax and structural exports.".to_string(),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_graphs_never_silently_compare_as_empty() {
        let empty = json!({"nodes": [], "edges": []});
        for invalid in [
            json!({"nodes": null}),
            json!({"nodes": "not an array"}),
            json!({"nodes": [{"node_id": "missing_path"}]}),
            json!({"nodes": [{"path": " "}]}),
            json!({"nodes": [{"path": "a.js"}, {"path": "a.js"}]}),
        ] {
            assert!(ApplicationDiffer::compare_applications(&invalid, &empty).is_err());
            assert!(ApplicationDiffer::compare_applications(&empty, &invalid).is_err());
            assert!(
                ApplicationDiffer::compare_export_shapes(
                    &invalid, "a.js", "f", &empty, "a.js", "f"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn diffs_identical_applications_as_unchanged() {
        let app = json!({
            "nodes": [
                {
                    "node_id": "n1",
                    "kind": "source-module",
                    "identity": {
                        "path": "src/index.js",
                        "artifact_sha256": "abc123hash"
                    },
                    "observations": [{
                        "properties": {
                            "exports": [{"name": "run", "kind": "named", "type_only": false}],
                            "functions": [{"name": "run", "params": 1, "is_async": false}]
                        }
                    }]
                }
            ],
            "edges": []
        });

        let diff = ApplicationDiffer::compare_applications(&app, &app).unwrap();
        assert_eq!(diff.summary.unchanged_count, 1);
        assert_eq!(diff.summary.added_count, 0);
        assert_eq!(diff.summary.removed_count, 0);
        assert_eq!(diff.summary.changed_count, 0);
    }

    #[test]
    fn diffs_added_and_removed_modules() {
        let left = json!({
            "nodes": [
                {
                    "node_id": "n1",
                    "identity": { "path": "src/old.js", "artifact_sha256": "111" }
                }
            ],
            "edges": []
        });

        let right = json!({
            "nodes": [
                {
                    "node_id": "n2",
                    "identity": { "path": "src/new.js", "artifact_sha256": "222" }
                }
            ],
            "edges": []
        });

        let diff = ApplicationDiffer::compare_applications(&left, &right).unwrap();
        assert_eq!(diff.added_modules, vec!["src/new.js"]);
        assert_eq!(diff.removed_modules, vec!["src/old.js"]);
        assert_eq!(diff.summary.added_count, 1);
        assert_eq!(diff.summary.removed_count, 1);
    }

    #[test]
    fn compares_export_shapes_correctly() {
        let left = json!({
            "nodes": [{
                "identity": { "path": "src/api.js" },
                "observations": [{
                    "properties": {
                        "exports": [{"name": "getData", "kind": "named", "type_only": false}],
                        "functions": [{"name": "getData", "params": 1, "is_async": false}]
                    }
                }]
            }]
        });

        let right = json!({
            "nodes": [{
                "identity": { "path": "src/api.js" },
                "observations": [{
                    "properties": {
                        "exports": [{"name": "getData", "kind": "named", "type_only": false}],
                        "functions": [{"name": "getData", "params": 2, "is_async": true}]
                    }
                }]
            }]
        });

        let diff = ApplicationDiffer::compare_export_shapes(
            &left,
            "src/api.js",
            "getData",
            &right,
            "src/api.js",
            "getData",
        )
        .unwrap();

        assert!(!diff.shape_compatible);
        assert_eq!(diff.status, "changed");
        assert_eq!(diff.differences.len(), 2);
    }
}
