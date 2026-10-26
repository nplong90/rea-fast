use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::analyze::FileAnalysis;
use crate::graph::Dependency;
use crate::semantics::{self, SemanticGraph, SemanticNode};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SeedKind {
    NodeId,
    Route,
    String,
    Channel,
    Module,
    NativeExport,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MatchMode {
    Exact,
    Contains,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeatureSeed {
    pub kind: SeedKind,
    pub value: String,
    #[serde(rename = "match", default = "default_match")]
    pub match_mode: MatchMode,
    #[serde(default = "default_case_sensitive")]
    pub case_sensitive: bool,
}

fn default_match() -> MatchMode {
    MatchMode::Exact
}

fn default_case_sensitive() -> bool {
    true
}

impl FeatureSeed {
    pub fn matches(&self, candidate: &str) -> bool {
        let (cand, val) = if self.case_sensitive {
            (candidate.to_string(), self.value.clone())
        } else {
            (candidate.to_lowercase(), self.value.to_lowercase())
        };

        match self.match_mode {
            MatchMode::Exact => cand == val,
            MatchMode::Contains => cand.contains(&val),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TraceDirection {
    Outgoing,
    Incoming,
    Both,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchedSeed {
    pub kind: SeedKind,
    pub matched_value: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeatureTraceEdge {
    pub source: String,
    pub target: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeatureTraceResult {
    pub seed: FeatureSeed,
    pub direction: TraceDirection,
    pub matched_seeds: Vec<MatchedSeed>,
    pub visited_modules: Vec<String>,
    pub visited_nodes: Vec<SemanticNode>,
    pub trace_edges: Vec<FeatureTraceEdge>,
    pub paths: Vec<Vec<String>>,
    pub reachable_sinks: Vec<String>,
}

pub struct ApplicationFeatureTracer<'a> {
    pub files: &'a [FileAnalysis],
    pub dependencies: &'a [Vec<Dependency<'a>>],
    pub semantic_graphs: Option<&'a HashMap<String, SemanticGraph>>,
}

impl<'a> ApplicationFeatureTracer<'a> {
    pub fn new(
        files: &'a [FileAnalysis],
        dependencies: &'a [Vec<Dependency<'a>>],
        semantic_graphs: Option<&'a HashMap<String, SemanticGraph>>,
    ) -> Self {
        Self {
            files,
            dependencies,
            semantic_graphs,
        }
    }

    pub fn trace(&self, seed: &FeatureSeed, direction: TraceDirection) -> FeatureTraceResult {
        let mut matched_seeds = Vec::new();
        let mut initial_modules = HashSet::new();

        // 1. Find matched seeds across files
        for (idx, file) in self.files.iter().enumerate() {
            let mut file_matched = false;

            match seed.kind {
                SeedKind::Module => {
                    if seed.matches(&file.path) {
                        matched_seeds.push(MatchedSeed {
                            kind: SeedKind::Module,
                            matched_value: file.path.clone(),
                            file: file.path.clone(),
                            node_id: Some(format!("mod:{}", file.path)),
                        });
                        file_matched = true;
                    }
                }
                SeedKind::String | SeedKind::Route | SeedKind::Channel => {
                    // Check imports / exports / symbols
                    for imp in &file.imports {
                        if let Some(src) = &imp.source {
                            if seed.matches(src) {
                                matched_seeds.push(MatchedSeed {
                                    kind: seed.kind.clone(),
                                    matched_value: src.clone(),
                                    file: file.path.clone(),
                                    node_id: None,
                                });
                                file_matched = true;
                            }
                        }
                    }
                    for exp in &file.exports {
                        if seed.matches(&exp.name) {
                            matched_seeds.push(MatchedSeed {
                                kind: seed.kind.clone(),
                                matched_value: exp.name.clone(),
                                file: file.path.clone(),
                                node_id: Some(format!("{}:exp:{}", file.path, exp.name)),
                            });
                            file_matched = true;
                        }
                    }
                    for func in &file.functions {
                        if func.name != "<anonymous>" && seed.matches(&func.name) {
                            matched_seeds.push(MatchedSeed {
                                kind: seed.kind.clone(),
                                matched_value: func.name.clone(),
                                file: file.path.clone(),
                                node_id: Some(format!("{}:fn:{}", file.path, func.name)),
                            });
                            file_matched = true;
                        }
                    }
                }
                SeedKind::NativeExport => {
                    for exp in &file.exports {
                        if seed.matches(&exp.name) {
                            matched_seeds.push(MatchedSeed {
                                kind: SeedKind::NativeExport,
                                matched_value: exp.name.clone(),
                                file: file.path.clone(),
                                node_id: Some(format!("{}:exp:{}", file.path, exp.name)),
                            });
                            file_matched = true;
                        }
                    }
                }
                SeedKind::NodeId => {
                    if seed.matches(&format!("mod:{}", file.path)) {
                        matched_seeds.push(MatchedSeed {
                            kind: SeedKind::NodeId,
                            matched_value: file.path.clone(),
                            file: file.path.clone(),
                            node_id: Some(format!("mod:{}", file.path)),
                        });
                        file_matched = true;
                    }
                }
            }

            // Also search inside semantic graph if available
            if let Some(sg_map) = self.semantic_graphs {
                if let Some(sg) = sg_map.get(&file.path) {
                    for node in &sg.nodes {
                        let matches_node = match seed.kind {
                            SeedKind::NodeId => seed.matches(&node.id),
                            SeedKind::String | SeedKind::Route => {
                                node.value.as_ref().is_some_and(|v| seed.matches(v))
                                    || seed.matches(&node.name)
                            }
                            SeedKind::Channel => {
                                node.class == semantics::SemanticNodeClass::Event
                                    && (seed.matches(&node.name)
                                        || node.value.as_ref().is_some_and(|v| seed.matches(v)))
                            }
                            SeedKind::Module => node.class == semantics::SemanticNodeClass::Module && seed.matches(&node.name),
                            SeedKind::NativeExport => {
                                node.class == semantics::SemanticNodeClass::Boundary && seed.matches(&node.name)
                            }
                        };

                        if matches_node {
                            matched_seeds.push(MatchedSeed {
                                kind: seed.kind.clone(),
                                matched_value: node.name.clone(),
                                file: file.path.clone(),
                                node_id: Some(node.id.clone()),
                            });
                            file_matched = true;
                        }
                    }
                }
            }

            if file_matched {
                initial_modules.insert(idx);
            }
        }

        // Build adjacency map for module dependencies
        let mut forward_dep: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut backward_dep: HashMap<usize, Vec<usize>> = HashMap::new();

        for (from_idx, file_deps) in self.dependencies.iter().enumerate() {
            for dep in file_deps {
                if let Some(to_idx) = dep.target_index {
                    forward_dep.entry(from_idx).or_default().push(to_idx);
                    backward_dep.entry(to_idx).or_default().push(from_idx);
                }
            }
        }

        // BFS traversal over modules
        let mut visited_mod_indices = HashSet::new();
        let mut trace_edges = Vec::new();
        let mut queue = VecDeque::new();
        let mut parent_map: HashMap<usize, Vec<usize>> = HashMap::new();

        for &mod_idx in &initial_modules {
            visited_mod_indices.insert(mod_idx);
            queue.push_back((mod_idx, 0usize));
        }

        while let Some((curr_idx, depth)) = queue.pop_front() {
            if depth >= 32 {
                continue;
            }

            let mut neighbors = Vec::new();

            if matches!(direction, TraceDirection::Outgoing | TraceDirection::Both) {
                if let Some(targets) = forward_dep.get(&curr_idx) {
                    for &target_idx in targets {
                        neighbors.push((target_idx, "imports"));
                    }
                }
            }

            if matches!(direction, TraceDirection::Incoming | TraceDirection::Both) {
                if let Some(sources) = backward_dep.get(&curr_idx) {
                    for &src_idx in sources {
                        neighbors.push((src_idx, "imported-by"));
                    }
                }
            }

            for (next_idx, edge_kind) in neighbors {
                let from_path = &self.files[curr_idx].path;
                let to_path = &self.files[next_idx].path;

                trace_edges.push(FeatureTraceEdge {
                    source: from_path.clone(),
                    target: to_path.clone(),
                    kind: edge_kind.to_string(),
                });

                if visited_mod_indices.insert(next_idx) {
                    parent_map.entry(next_idx).or_default().push(curr_idx);
                    queue.push_back((next_idx, depth + 1));
                }
            }
        }

        // Collect visited module paths
        let mut visited_modules: Vec<String> = visited_mod_indices
            .iter()
            .map(|&idx| self.files[idx].path.clone())
            .collect();
        visited_modules.sort();

        // Extract reachable sinks (leaf modules with no outgoing visited edges)
        let mut reachable_sinks = Vec::new();
        for &idx in &visited_mod_indices {
            let has_outgoing = forward_dep
                .get(&idx)
                .is_some_and(|targets| targets.iter().any(|t| visited_mod_indices.contains(t)));
            if !has_outgoing && !initial_modules.contains(&idx) {
                reachable_sinks.push(self.files[idx].path.clone());
            }
        }
        reachable_sinks.sort();

        // Path reconstruction from initial to sinks
        let mut paths = Vec::new();
        for sink in &reachable_sinks {
            if let Some(sink_idx) = self.files.iter().position(|f| f.path == *sink) {
                let mut path = vec![sink.clone()];
                let mut curr = sink_idx;
                while let Some(parents) = parent_map.get(&curr) {
                    if let Some(&p) = parents.first() {
                        path.push(self.files[p].path.clone());
                        curr = p;
                        if initial_modules.contains(&p) {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                path.reverse();
                paths.push(path);
            }
        }

        // Collect semantic nodes in visited modules if semantic graphs are available
        let mut visited_nodes = Vec::new();
        if let Some(sg_map) = self.semantic_graphs {
            for mod_path in &visited_modules {
                if let Some(sg) = sg_map.get(mod_path) {
                    visited_nodes.extend(sg.nodes.clone());
                }
            }
        }

        FeatureTraceResult {
            seed: seed.clone(),
            direction,
            matched_seeds,
            visited_modules,
            visited_nodes,
            trace_edges,
            paths,
            reachable_sinks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{ExportInfo, FunctionInfo, Location, Position};

    #[test]
    fn traces_feature_seed_across_modules() {
        let dummy_loc = Location {
            start: Position { line: 1, column: 0 },
            end: Position { line: 1, column: 10 },
            byte_start: 0,
            byte_end: 10,
        };
        let files = vec![
            FileAnalysis {
                path: "src/index.js".into(),
                exports: vec![ExportInfo {
                    name: "loginHandler".into(),
                    local: None,
                    source: None,
                    kind: "named",
                    type_only: false,
                    location: dummy_loc.clone(),
                }],
                ..Default::default()
            },
            FileAnalysis {
                path: "src/auth.js".into(),
                functions: vec![FunctionInfo {
                    name: "loginHandler".into(),
                    params: 2,
                    is_async: false,
                    is_generator: false,
                    type_only: false,
                    location: dummy_loc.clone(),
                }],
                ..Default::default()
            },
            FileAnalysis {
                path: "src/db.js".into(),
                ..Default::default()
            },
        ];

        let dependencies = vec![
            vec![Dependency {
                source: Some("./auth"),
                target: Some("src/auth.js"),
                kind: "static-import",
                type_only: false,
                resolution: "relative-source-inference",
                location: &dummy_loc,
                target_index: Some(1),
            }],
            vec![Dependency {
                source: Some("./db"),
                target: Some("src/db.js"),
                kind: "static-import",
                type_only: false,
                resolution: "relative-source-inference",
                location: &dummy_loc,
                target_index: Some(2),
            }],
            vec![],
        ];

        let tracer = ApplicationFeatureTracer::new(&files, &dependencies, None);
        let seed = FeatureSeed {
            kind: SeedKind::String,
            value: "loginHandler".into(),
            match_mode: MatchMode::Exact,
            case_sensitive: true,
        };

        let result = tracer.trace(&seed, TraceDirection::Outgoing);
        assert!(!result.matched_seeds.is_empty());
        assert!(result.visited_modules.contains(&"src/index.js".to_string()));
        assert!(result.visited_modules.contains(&"src/auth.js".to_string()));
        assert!(result.visited_modules.contains(&"src/db.js".to_string()));
        assert_eq!(result.reachable_sinks, vec!["src/db.js"]);
    }
}
