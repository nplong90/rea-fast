use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::sync::{OnceLock, RwLock};

const MAX_EVIDENCE_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

/// Deterministic JSON encoding for locally stored evidence.
/// This is not a complete RFC 8785 implementation (notably float formatting).
pub fn canonicalize_json(val: &Value) -> String {
    match val {
        Value::Null => "null".to_string(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s)),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonicalize_json).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(obj) => {
            // RFC 8785 specifies UTF-16 key order, which differs from UTF-8
            // lexical order for some supplementary-plane characters.
            let mut sorted: Vec<_> = obj.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            let entries: Vec<String> = sorted
                .into_iter()
                .map(|(k, v)| {
                    let key_str = serde_json::to_string(k).unwrap_or_else(|_| format!("\"{}\"", k));
                    format!("{}:{}", key_str, canonicalize_json(v))
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
    }
}

pub fn digest_value(val: &Value) -> String {
    let canonical = canonicalize_json(val);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Default, Serialize, Deserialize)]
pub struct EvidenceStore {
    pub records: HashMap<String, Value>,
    pub unknowns: HashMap<String, Value>,
    pub scenarios: Vec<Value>,
    pub captures: Vec<Value>,
    pub artifacts: Vec<Value>,
    pub providers: Vec<Value>,
    pub environments: Vec<Value>,
}

static STORE: OnceLock<RwLock<EvidenceStore>> = OnceLock::new();

fn get_store() -> &'static RwLock<EvidenceStore> {
    STORE.get_or_init(|| RwLock::new(EvidenceStore::default()))
}

pub fn add_record(mut record: Value) -> String {
    let id = record
        .get("evidence_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("ev_{}", digest_value(&record)));

    if record.get("evidence_id").is_none()
        && let Some(obj) = record.as_object_mut()
    {
        obj.insert("evidence_id".to_string(), json!(id));
    }
    let mut store = get_store().write().unwrap();
    store.records.insert(id.clone(), record);
    id
}

pub fn get_record(evidence_id: &str) -> Option<Value> {
    let store = get_store().read().unwrap();
    store.records.get(evidence_id).cloned()
}

pub fn get_evidence_bundle(args: &Value) -> Value {
    let detail = args
        .get("detail")
        .and_then(|v| v.as_str())
        .unwrap_or("complete");
    let store = get_store().read().unwrap();

    let mut records_vec: Vec<Value> = store.records.values().cloned().collect();
    let mut unknowns_vec: Vec<Value> = store.unknowns.values().cloned().collect();
    records_vec.sort_by_key(|r| r["evidence_id"].as_str().unwrap_or("").to_string());
    unknowns_vec.sort_by_key(|u| u["unknown_id"].as_str().unwrap_or("").to_string());

    if detail == "summary" {
        json!({
            "status": "complete",
            "summary": {
                "records_count": records_vec.len(),
                "unknowns_count": unknowns_vec.len(),
                "scenarios_count": store.scenarios.len(),
                "captures_count": store.captures.len(),
                "artifacts_count": store.artifacts.len()
            }
        })
    } else {
        json!({
            "artifacts": store.artifacts,
            "providers": store.providers,
            "environments": store.environments,
            "scenarios": store.scenarios,
            "captures": store.captures,
            "unknowns": unknowns_vec,
            "records": records_vec
        })
    }
}

pub fn export_evidence_bundle(args: &Value) -> Value {
    let path_str = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return json!({ "status": "error", "message": "Missing 'path' argument" }),
    };
    let overwrite = args
        .get("overwrite")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let p = std::path::Path::new(path_str);
    if p.exists() && !overwrite {
        return json!({ "status": "error", "message": format!("File {path_str} already exists. Set overwrite: true to replace.") });
    }

    let bundle = get_evidence_bundle(&json!({ "detail": "complete" }));
    let canonical = canonicalize_json(&bundle);
    if let Err(e) = fs::write(p, canonical) {
        return json!({ "status": "error", "message": format!("Failed to write bundle: {e}") });
    }
    json!({ "status": "exported", "path": path_str, "sha256": digest_value(&bundle) })
}

pub fn import_evidence_bundle(args: &Value) -> Value {
    let path_str = match args.get("path").and_then(Value::as_str) {
        Some(path) => path,
        None => return json!({"status": "error", "message": "Missing 'path' argument"}),
    };
    // A bounded streaming read also resists files growing after open.
    let file = match fs::File::open(path_str) {
        Ok(file) => file,
        Err(error) => {
            return json!({"status": "error", "message": format!("Cannot open bundle: {error}")});
        }
    };
    let mut data = String::new();
    if let Err(error) = file
        .take(MAX_EVIDENCE_BUNDLE_BYTES + 1)
        .read_to_string(&mut data)
    {
        return json!({"status": "error", "message": format!("Cannot read bundle: {error}")});
    }
    if data.len() as u64 > MAX_EVIDENCE_BUNDLE_BYTES {
        return json!({"status": "error", "message": "Evidence bundle exceeds 64 MiB limit"});
    }
    let parsed: Value = match serde_json::from_str(&data) {
        Ok(value) => value,
        Err(error) => {
            return json!({"status": "error", "message": format!("Invalid JSON: {error}")});
        }
    };
    if !parsed.is_object() {
        return json!({"status": "error", "message": "Evidence bundle must be a JSON object"});
    }

    let digest = digest_value(&parsed);
    if args
        .get("expected_sha256")
        .is_some_and(|value| !value.is_string())
    {
        return json!({"status": "error", "message": "expected_sha256 must be a string"});
    }
    let expected = args.get("expected_sha256").and_then(Value::as_str);
    if expected.is_some_and(|value| !value.eq_ignore_ascii_case(&digest)) {
        return json!({
            "status": "error",
            "message": "Evidence bundle SHA-256 mismatch",
            "observed_sha256": digest
        });
    }

    let records = match parsed.get("records").and_then(Value::as_array) {
        Some(records) => records,
        None => return json!({"status": "error", "message": "Missing/invalid records array"}),
    };
    let unknowns = match parsed.get("unknowns").and_then(Value::as_array) {
        Some(unknowns) => unknowns,
        None => return json!({"status": "error", "message": "Missing/invalid unknowns array"}),
    };
    let mut imported_records = HashMap::<String, Value>::new();
    let mut imported_unknowns = HashMap::<String, Value>::new();
    for (entries, key, out) in [
        (records, "evidence_id", &mut imported_records),
        (unknowns, "unknown_id", &mut imported_unknowns),
    ] {
        for entry in entries {
            let Some(id) = entry
                .get(key)
                .and_then(Value::as_str)
                .filter(|id| !id.trim().is_empty())
            else {
                return json!({"status": "error", "message": format!("Evidence entry missing {key}")});
            };
            if out.insert(id.to_string(), entry.clone()).is_some() {
                return json!({"status": "error", "message": format!("Duplicate bundle ID: {id}")});
            }
        }
    }

    for section in [
        "scenarios",
        "captures",
        "artifacts",
        "providers",
        "environments",
    ] {
        if parsed.get(section).is_some_and(|value| !value.is_array()) {
            return json!({"status": "error", "message": format!("Invalid {section} array")});
        }
    }

    let mut store = get_store().write().unwrap();
    for (id, record) in &imported_records {
        if store
            .records
            .get(id)
            .is_some_and(|existing| existing != record)
        {
            return json!({"status": "error", "message": format!("Conflicting evidence ID: {id}")});
        }
    }
    for (id, unknown) in &imported_unknowns {
        if store
            .unknowns
            .get(id)
            .is_some_and(|existing| existing != unknown)
        {
            return json!({"status": "error", "message": format!("Conflicting unknown ID: {id}")});
        }
    }
    // No mutation until the full bundle and every existing-ID collision are checked.
    let record_count = imported_records.len();
    let unknown_count = imported_unknowns.len();
    store.records.extend(imported_records);
    store.unknowns.extend(imported_unknowns);
    for (key, destination) in [
        ("scenarios", &mut store.scenarios),
        ("captures", &mut store.captures),
        ("artifacts", &mut store.artifacts),
        ("providers", &mut store.providers),
        ("environments", &mut store.environments),
    ] {
        if let Some(items) = parsed.get(key).and_then(Value::as_array) {
            for item in items {
                if !destination.contains(item) {
                    destination.push(item.clone());
                }
            }
        }
    }

    json!({
        "status": "imported",
        "imported_records": record_count,
        "imported_unknowns": unknown_count,
        "sha256": digest,
        "digest_verified": expected.is_some(),
        "authenticity_verified": false
    })
}

pub fn record_unknown(args: &Value) -> Value {
    let question = args.get("question").and_then(|v| v.as_str()).unwrap_or("");
    let domain = args
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("general");
    let severity = args
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("medium");
    let unknown_id = format!("unk_{:x}", {
        let mut hasher = Sha256::new();
        hasher.update(question.as_bytes());
        hasher.update(domain.as_bytes());
        hasher.finalize()
    });

    let record = json!({
        "unknown_id": unknown_id,
        "revision": 1,
        "status": "open",
        "severity": severity,
        "domain": domain,
        "question": question,
        "supporting_evidence_ids": args.get("supporting_evidence_ids").cloned().unwrap_or(json!([])),
        "contradicting_evidence_ids": args.get("contradicting_evidence_ids").cloned().unwrap_or(json!([])),
        "recommended_probes": args.get("recommended_probes").cloned().unwrap_or(json!([])),
        "relationships": args.get("relationships").cloned().unwrap_or(json!([])),
        "resolution": null
    });

    let mut store = get_store().write().unwrap();
    store.unknowns.insert(unknown_id.clone(), record.clone());
    record
}

pub fn update_unknown(args: &Value) -> Value {
    let unknown_id = match args.get("unknown_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return json!({ "status": "error", "message": "Missing unknown_id" }),
    };
    let expected_rev = args
        .get("expected_revision")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    let mut store = get_store().write().unwrap();
    if let Some(existing) = store.unknowns.get_mut(unknown_id) {
        let cur_rev = existing
            .get("revision")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        if cur_rev != expected_rev {
            return json!({ "status": "stale_revision", "current_revision": cur_rev, "expected_revision": expected_rev });
        }
        if let Some(obj) = existing.as_object_mut() {
            obj.insert("revision".to_string(), json!(cur_rev + 1));
            if let Some(status) = args.get("status") {
                obj.insert("status".to_string(), status.clone());
            }
            if let Some(res) = args.get("resolution") {
                obj.insert("resolution".to_string(), res.clone());
            }
        }
        existing.clone()
    } else {
        json!({ "status": "error", "message": format!("Unknown {unknown_id} not found") })
    }
}

pub fn list_unknowns(args: &Value) -> Value {
    let store = get_store().read().unwrap();
    let status_filter = args.get("status").and_then(|v| v.as_str());
    let severity_filter = args.get("severity").and_then(|v| v.as_str());
    let domain_filter = args.get("domain").and_then(|v| v.as_str());
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;

    let mut matches: Vec<&Value> = store
        .unknowns
        .values()
        .filter(|u| {
            if let Some(sf) = status_filter
                && u.get("status").and_then(|s| s.as_str()) != Some(sf)
            {
                return false;
            }
            if let Some(sv) = severity_filter
                && u.get("severity").and_then(|s| s.as_str()) != Some(sv)
            {
                return false;
            }
            if let Some(df) = domain_filter
                && u.get("domain").and_then(|s| s.as_str()) != Some(df)
            {
                return false;
            }
            true
        })
        .collect();

    matches.sort_by_key(|u| u.get("unknown_id").and_then(|s| s.as_str()).unwrap_or(""));
    let total = matches.len();
    let page: Vec<Value> = matches
        .into_iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect();

    json!({
        "total": total,
        "offset": offset,
        "limit": limit,
        "unknowns": page
    })
}

pub fn verify_unknown_resolution(args: &Value) -> Value {
    let unknown_id = match args.get("unknown_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return json!({ "status": "error", "message": "Missing unknown_id" }),
    };
    let store = get_store().read().unwrap();
    if let Some(unk) = store.unknowns.get(unknown_id) {
        json!({
            "unknown_id": unknown_id,
            "status": "unverified",
            "evidence_intact": null,
            "declared_status": unk.get("status"),
            "reason": "Evidence references and the resolution claim have not been authenticated"
        })
    } else {
        json!({ "status": "error", "message": format!("Unknown {unknown_id} not found") })
    }
}

pub fn inspect_analysis_view(args: &Value) -> Value {
    let source = args.get("source");
    let view = args.get("view");
    let kind = view
        .and_then(|v| v.get("kind"))
        .and_then(|k| k.as_str())
        .unwrap_or("summary");

    let ev_id = source
        .and_then(|s| s.get("evidence_id"))
        .and_then(|id| id.as_str())
        .unwrap_or("");

    let rec = get_record(ev_id);
    match rec {
        Some(val) => json!({
            "status": "complete",
            "evidence_id": ev_id,
            "kind": kind,
            "view": val
        }),
        None => json!({
            "status": "unavailable",
            "evidence_id": ev_id,
            "message": format!("Evidence record {ev_id} not retained in active session")
        }),
    }
}

pub fn compare_artifacts(args: &Value) -> Value {
    let (Some(left), Some(right)) = (args.get("left"), args.get("right")) else {
        return json!({"status": "error", "message": "Both 'left' and 'right' are required"});
    };
    let left_hash = digest_value(left);
    let right_hash = digest_value(right);

    json!({
        "status": "complete",
        "identical": left_hash == right_hash,
        "left_sha256": left_hash,
        "right_sha256": right_hash,
        "differences": if left_hash == right_hash { json!([]) } else { json!(["content_digest_mismatch"]) }
    })
}

pub fn compare_bundles(args: &Value) -> Value {
    let (Some(left_path), Some(right_path)) = (
        args.get("left_bundle_path").and_then(|v| v.as_str()),
        args.get("right_bundle_path").and_then(|v| v.as_str()),
    ) else {
        return json!({"status": "error", "message": "Both bundle paths are required"});
    };

    let left_data = match fs::read_to_string(left_path) {
        Ok(data) => data,
        Err(err) => {
            return json!({"status": "error", "message": format!("Cannot read left bundle: {err}")});
        }
    };
    let right_data = match fs::read_to_string(right_path) {
        Ok(data) => data,
        Err(err) => {
            return json!({"status": "error", "message": format!("Cannot read right bundle: {err}")});
        }
    };

    let left_val: Value = match serde_json::from_str(&left_data) {
        Ok(value) => value,
        Err(err) => {
            return json!({"status": "error", "message": format!("Invalid left bundle JSON: {err}")});
        }
    };
    let right_val: Value = match serde_json::from_str(&right_data) {
        Ok(value) => value,
        Err(err) => {
            return json!({"status": "error", "message": format!("Invalid right bundle JSON: {err}")});
        }
    };

    json!({
        "status": "complete",
        "left_records": left_val.get("records").and_then(|r| r.as_array()).map(|a| a.len()).unwrap_or(0),
        "right_records": right_val.get("records").and_then(|r| r.as_array()).map(|a| a.len()).unwrap_or(0),
        "identical": canonicalize_json(&left_val) == canonicalize_json(&right_val)
    })
}

pub fn build_reconstruction_obligation_ledger(args: &Value) -> Value {
    let reviewed = args.get("reviewed_obligations").and_then(|v| v.as_array());
    let count = reviewed.map(|a| a.len()).unwrap_or(0);
    let closure_digest = digest_value(args);

    json!({
        "status": "unavailable",
        "closure_digest": closure_digest,
        "obligations_count": count,
        "violations": null,
        "reason": "Obligation validation and evidence authentication are not implemented"
    })
}

pub fn evaluate_reconstruction_coverage(args: &Value) -> Value {
    let boundary = args
        .get("boundary_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    json!({
        "status": "unavailable",
        "boundary_id": boundary,
        "coverage_percentage": null,
        "uncovered_surfaces": null,
        "reason": "No authenticated coverage inventory was evaluated"
    })
}

pub fn verify_reconstruction(_args: &Value) -> Value {
    json!({
        "status": "unavailable",
        "claims_verified": false,
        "violations": null,
        "reason": "Reconstruction verification requires evidence-backed claim evaluation"
    })
}

pub fn build_call_path(args: &Value) -> Value {
    let start = args
        .get("start")
        .and_then(|s| s.get("address"))
        .and_then(|a| a.as_str())
        .unwrap_or("");
    let goal = args
        .get("goal")
        .and_then(|s| s.get("address"))
        .and_then(|a| a.as_str())
        .unwrap_or("");
    json!({
        "status": "unavailable",
        "start": start,
        "goal": goal,
        "path": null,
        "distance": null,
        "reachability": "unknown",
        "reason": "No validated call graph was traversed"
    })
}

pub fn compare_functions(args: &Value) -> Value {
    let left = args.get("left");
    let right = args.get("right");
    let left_h = left.map(digest_value).unwrap_or_default();
    let right_h = right.map(digest_value).unwrap_or_default();
    json!({
        "status": "unavailable",
        "identical_input_payload": left.is_some() && right.is_some() && left_h == right_h,
        "structural_similarity": null,
        "reason": "Function bodies, graph structure and equivalence have not been compared"
    })
}

pub fn find_changed_behavior(args: &Value) -> Value {
    let comparisons = args.get("comparisons").and_then(|c| c.as_array());
    json!({
        "status": "unavailable",
        "findings_count": comparisons.map(|c| c.len()).unwrap_or(0),
        "behavioral_changes": null,
        "reason": "Behavioral changes cannot be inferred from comparison count alone"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_import_rejects_invalid_data_without_partial_mutation() {
        let unique = format!(
            "ev_import_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let file = std::env::temp_dir().join(format!("{unique}.json"));
        let invalid = json!({
            "records": [{"evidence_id": unique}, {"bad": "missing id"}],
            "unknowns": []
        });
        fs::write(&file, canonicalize_json(&invalid)).unwrap();
        let failed = import_evidence_bundle(&json!({"path": file}));
        assert_eq!(failed["status"], "error");
        assert!(get_record(&unique).is_none());

        let valid = json!({
            "records": [{"evidence_id": unique, "observed": true}],
            "unknowns": [],
            "scenarios": [{"source": unique}]
        });
        fs::write(&file, canonicalize_json(&valid)).unwrap();
        let mismatched = import_evidence_bundle(&json!({
            "path": file,
            "expected_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
        }));
        assert_eq!(mismatched["status"], "error");
        assert!(get_record(&unique).is_none());

        let imported = import_evidence_bundle(&json!({
            "path": file,
            "expected_sha256": digest_value(&valid)
        }));
        assert_eq!(imported["status"], "imported");
        assert_eq!(imported["digest_verified"], true);
        assert_eq!(imported["authenticity_verified"], false);
        assert_eq!(get_record(&unique).unwrap()["observed"], true);
        assert!(
            get_evidence_bundle(&json!({}))["scenarios"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["source"] == unique)
        );

        let conflicting = json!({
            "records": [{"evidence_id": unique, "observed": false}],
            "unknowns": []
        });
        fs::write(&file, canonicalize_json(&conflicting)).unwrap();
        let failed = import_evidence_bundle(&json!({"path": file}));
        assert_eq!(failed["status"], "error");
        assert_eq!(get_record(&unique).unwrap()["observed"], true);
        fs::remove_file(file).unwrap();
    }

    #[test]
    fn test_canonical_json_sorting() {
        let val = json!({
            "zebra": 1,
            "apple": 2,
            "nested": {
                "beta": true,
                "alpha": false
            }
        });
        let canonical = canonicalize_json(&val);
        assert_eq!(
            canonical,
            r#"{"apple":2,"nested":{"alpha":false,"beta":true},"zebra":1}"#
        );
    }

    #[test]
    fn test_evidence_unknown_lifecycle() {
        let unk = record_unknown(&json!({
            "question": "What is the entry point?",
            "domain": "binary"
        }));
        let id = unk.get("unknown_id").unwrap().as_str().unwrap();

        let list = list_unknowns(&json!({ "domain": "binary" }));
        assert_eq!(list.get("total").unwrap().as_u64(), Some(1));

        let updated = update_unknown(&json!({
            "unknown_id": id,
            "expected_revision": 1,
            "status": "resolved"
        }));
        assert_eq!(updated.get("status").unwrap().as_str(), Some("resolved"));
        let verification = verify_unknown_resolution(&json!({"unknown_id": id}));
        assert_eq!(verification["status"], "unverified");
        assert!(verification["evidence_intact"].is_null());
    }

    #[test]
    fn incomplete_reconstruction_never_claims_success() {
        assert_eq!(
            evaluate_reconstruction_coverage(&json!({}))["coverage_percentage"],
            Value::Null
        );
        assert_eq!(verify_reconstruction(&json!({}))["status"], "unavailable");
        assert_eq!(build_call_path(&json!({}))["reachability"], "unknown");
        assert!(
            compare_functions(&json!({"left": {}, "right": {}}))["structural_similarity"].is_null()
        );
        assert_eq!(
            find_changed_behavior(&json!({"comparisons": []}))["status"],
            "unavailable"
        );
        assert_eq!(
            build_reconstruction_obligation_ledger(&json!({}))["status"],
            "unavailable"
        );
    }

    #[test]
    fn bundle_comparison_refuses_missing_or_invalid_sources() {
        assert_eq!(compare_artifacts(&json!({}))["status"], "error");
        assert_eq!(compare_bundles(&json!({}))["status"], "error");
        let nonexistent =
            std::env::temp_dir().join(format!("rea_fast_missing_bundle_{}", std::process::id()));
        let result = compare_bundles(&json!({
            "left_bundle_path": nonexistent,
            "right_bundle_path": nonexistent
        }));
        assert_eq!(result["status"], "error");
    }
}
