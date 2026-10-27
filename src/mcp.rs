use crate::{
    analyze::{self, FileAnalysis},
    asar::{self, AsarArchive, IntegrityPolicy},
    bundle::{ExtractionMode, RewriteLevel, SourceRecoverer},
    diff::ApplicationDiffer,
    dynamic_bridge::DynamicBridge,
    electron, fuses, graph,
    mobile::MobileInspector,
    native_binary::NativeInspector,
    pipeline::AuditPipeline,
    secrets::SecretScanner,
    semantics::{self, SemanticQuery},
    sourcemap::SourceMapExtractor,
    storage_pcap::StoragePcapInspector,
    tauri::TauriScanner,
    trace::{ApplicationFeatureTracer, FeatureSeed, TraceDirection},
};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    error::Error,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
};

fn is_asar(path: &Path) -> bool {
    path.extension().and_then(|s| s.to_str()) == Some("asar")
}

fn supported(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts")
    )
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut files = Vec::new();
    for entry in WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .require_git(false)
        .filter_entry(|entry| {
            !entry.file_type().is_some_and(|t| t.is_dir())
                || !matches!(entry.file_name().to_str(), Some("node_modules" | ".git"))
        })
        .build()
    {
        let entry = entry?;
        if entry.file_type().is_some_and(|t| t.is_file()) && supported(entry.path()) {
            files.push(entry.into_path());
        }
    }
    files.sort();
    Ok(files)
}

pub fn analyze_application_files(
    input: &Path,
    max_file_bytes: u64,
) -> Result<Vec<FileAnalysis>, Box<dyn Error>> {
    let input = input.canonicalize()?;
    let results: Vec<FileAnalysis> = if is_asar(&input) {
        let archive = AsarArchive::open(&input)?;
        let entries: Vec<_> = archive
            .entries
            .iter()
            .filter(|e| supported(Path::new(&e.path)))
            .cloned()
            .collect();
        if entries.is_empty() {
            return Err("No JS/TS files found in ASAR".into());
        }
        entries
            .par_iter()
            .map(|entry| {
                if entry.size > max_file_bytes {
                    return FileAnalysis {
                        path: entry.path.clone(),
                        error: Some(format!("File exceeds --max-file-bytes={max_file_bytes}")),
                        ..Default::default()
                    };
                }
                match archive.read_file(entry) {
                    Ok(bytes) => match std::str::from_utf8(&bytes) {
                        Ok(source) => analyze::analyze_source(source, &entry.path),
                        Err(_) => FileAnalysis {
                            path: entry.path.clone(),
                            error: Some("File is not valid UTF-8".into()),
                            ..Default::default()
                        },
                    },
                    Err(e) => FileAnalysis {
                        path: entry.path.clone(),
                        error: Some(e.to_string()),
                        ..Default::default()
                    },
                }
            })
            .collect()
    } else {
        let root = if input.is_file() {
            input.parent().ok_or("File has no parent")?
        } else {
            &input
        };
        let files = collect_files(&input)?;
        if files.is_empty() {
            return Err("No JS/TS files matched the ignore rules".into());
        }
        files
            .par_iter()
            .map(|path| analyze::analyze_file(path, root, max_file_bytes))
            .collect()
    };
    Ok(results)
}

pub fn analyze_application(input: &Path, max_file_bytes: u64) -> Result<Value, Box<dyn Error>> {
    let results = analyze_application_files(input, max_file_bytes)?;
    let deps = graph::dependencies(&results);
    let mut out = Vec::new();
    graph::write_graph(&mut out, &results, &deps, max_file_bytes)?;
    let val = serde_json::from_slice(&out)?;
    Ok(val)
}

fn resolve_graph_value(val: &Value) -> Result<Value, String> {
    if let Some(s) = val.as_str() {
        let path = Path::new(s);
        if path.exists() {
            return analyze_application(path, 16_777_216).map_err(|e| e.to_string());
        }
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            return resolve_graph_value(&parsed);
        }
    } else if let Some(obj) = val.as_object() {
        if obj.contains_key("nodes") {
            return Ok(val.clone());
        }
        if let Some(norm) = obj.get("normalized_result") {
            return resolve_graph_value(norm);
        }
        if let Some(raw) = obj.get("raw_result") {
            return resolve_graph_value(raw);
        }
        if let Some(p) = obj
            .get("input_path")
            .or_else(|| obj.get("path"))
            .and_then(|v| v.as_str())
        {
            let path = Path::new(p);
            if path.exists() {
                return analyze_application(path, 16_777_216).map_err(|e| e.to_string());
            }
        }
        if let Some(subj) = obj
            .get("subject")
            .and_then(|s| s.get("local_path"))
            .and_then(|v| v.as_str())
        {
            let path = Path::new(subj);
            if path.exists() {
                return analyze_application(path, 16_777_216).map_err(|e| e.to_string());
            }
        }
    }
    Ok(val.clone())
}

fn resolve_input_path(val: &Value) -> Option<PathBuf> {
    if let Some(s) = val.as_str() {
        let p = Path::new(s);
        if p.exists() {
            return Some(p.to_path_buf());
        }
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            return resolve_input_path(&parsed);
        }
    } else if let Some(obj) = val.as_object() {
        if let Some(p) = obj
            .get("input_path")
            .or_else(|| obj.get("path"))
            .and_then(|v| v.as_str())
        {
            let path = Path::new(p);
            if path.exists() {
                return Some(path.to_path_buf());
            }
        }
        if let Some(subj) = obj
            .get("subject")
            .and_then(|s| s.get("local_path"))
            .and_then(|v| v.as_str())
        {
            let path = Path::new(subj);
            if path.exists() {
                return Some(path.to_path_buf());
            }
        }
        if let Some(norm) = obj.get("normalized_result") {
            return resolve_input_path(norm);
        }
        if let Some(raw) = obj.get("raw_result") {
            return resolve_input_path(raw);
        }
    }
    None
}

pub fn build_application_semantic_graph(
    input: &Path,
) -> Result<semantics::SemanticGraph, Box<dyn Error>> {
    let input = input.canonicalize()?;
    let mut combined = semantics::SemanticGraph::default();
    if is_asar(&input) {
        let archive = AsarArchive::open(&input)?;
        for entry in &archive.entries {
            if supported(Path::new(&entry.path))
                && !entry.unpacked
                && let Ok(bytes) = archive.read_file(entry)
                && let Ok(source) = std::str::from_utf8(&bytes)
            {
                let g = semantics::build_semantic_graph(source, &entry.path);
                combined.nodes.extend(g.nodes);
                combined.edges.extend(g.edges);
            }
        }
    } else if input.is_file() {
        let source = std::fs::read_to_string(&input)?;
        let name = input
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("file.js");
        combined = semantics::build_semantic_graph(&source, name);
    } else {
        let root = &input;
        let files = collect_files(&input)?;
        for path in files {
            if let Ok(source) = std::fs::read_to_string(&path) {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                let g = semantics::build_semantic_graph(&source, &rel);
                combined.nodes.extend(g.nodes);
                combined.edges.extend(g.edges);
            }
        }
    }
    combined.edges.dedup();
    Ok(combined)
}

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Serialize)]
struct ToolContent {
    #[serde(rename = "type")]
    content_type: &'static str,
    text: String,
}

#[derive(Serialize)]
struct ToolResult {
    content: Vec<ToolContent>,
    #[serde(rename = "isError")]
    is_error: bool,
}

static ACTIVE_PROFILE_FULL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_profile_full(full: bool) {
    ACTIVE_PROFILE_FULL.store(full, std::sync::atomic::Ordering::Relaxed);
}

pub fn is_profile_full() -> bool {
    ACTIVE_PROFILE_FULL.load(std::sync::atomic::Ordering::Relaxed)
        || std::env::var("REA_MCP_PROFILE").as_deref() == Ok("full")
}

fn tool_list() -> Value {
    let tools = if is_profile_full() {
        crate::catalog::get_all_tools()
    } else {
        crate::catalog::get_core_tools()
    };
    let tools: Vec<Value> = tools.iter().map(crate::capabilities::advertise).collect();
    json!({
        "tools": tools
    })
}

pub fn handle_tool_call(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "rea_search_tools" => {
            let query = args
                .get("query")
                .or_else(|| args.get("q"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let matches = crate::catalog::search_tools(query);
            let mut totals = [0usize; 3];
            let tools: Vec<Value> = matches
                .iter()
                .map(|tool| {
                    let name = tool["name"].as_str().unwrap_or("");
                    match crate::capabilities::classify(name) {
                        crate::capabilities::Capability::Native => totals[0] += 1,
                        crate::capabilities::Capability::ExternalProvider => totals[1] += 1,
                        crate::capabilities::Capability::Unavailable => totals[2] += 1,
                    }
                    crate::capabilities::annotate(tool)
                })
                .collect();
            Ok(json!({
                "query": query,
                "count": tools.len(),
                "capability_counts": {
                    "native": totals[0],
                    "external-provider": totals[1],
                    "unavailable": totals[2]
                },
                "tools": tools
            }))
        }
        "rea_execute_tool" => {
            let target_name = args
                .get("tool_name")
                .or_else(|| args.get("name"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'tool_name' argument".to_string())?;
            // A meta-tool must never invoke itself: doing so recurses until the
            // MCP server exhausts its stack, taking down all active clients.
            if target_name == "rea_execute_tool" {
                return Err("rea_execute_tool cannot invoke itself".to_string());
            }
            if !crate::catalog::has_tool(target_name) {
                return Err(format!("Unknown tool: {target_name}"));
            }
            let empty = json!({});
            let target_args = args
                .get("arguments")
                .or_else(|| args.get("args"))
                .unwrap_or(&empty);
            if !target_args.is_object() {
                return Err("'arguments' must be an object".to_string());
            }
            handle_tool_call(target_name, target_args)
        }
        "inspect_electron_fuses" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let report = fuses::inspect_fuses(Path::new(path_str)).map_err(|e| e.to_string())?;
            serde_json::to_value(report).map_err(|e| e.to_string())
        }
        "analyze_javascript_application" => {
            let path_str = args
                .get("input_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'input_path' argument".to_string())?;
            let limit = args
                .get("max_file_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(16_777_216);

            analyze_application(Path::new(path_str), limit).map_err(|e| e.to_string())
        }
        "inspect_asar" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let archive = AsarArchive::open(Path::new(path_str)).map_err(|e| e.to_string())?;
            let total = archive.entries.len();
            let truncated = total > 100;
            let display_entries = if truncated {
                &archive.entries[..100]
            } else {
                &archive.entries[..]
            };
            let summary = json!({
                "path": path_str,
                "total_entries": total,
                "truncated": truncated,
                "returned_entries": display_entries.len(),
                "entries": display_entries.iter().map(|e| json!({
                    "path": e.path,
                    "size": e.size,
                    "offset": e.offset,
                    "unpacked": e.unpacked,
                    "executable": e.executable,
                    "integrity": e.integrity.as_ref().map(|i| json!({
                        "algorithm": i.algorithm,
                        "hash": i.hash,
                    })),
                })).collect::<Vec<_>>()
            });
            Ok(summary)
        }
        "analyze_electron_source" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let source = if let Some(s) = args.get("source").and_then(|v| v.as_str()) {
                s.to_string()
            } else {
                std::fs::read_to_string(path_str).map_err(|e| e.to_string())?
            };
            let findings = electron::analyze_electron_source(&source, path_str);
            serde_json::to_value(findings).map_err(|e| e.to_string())
        }
        "extract_artifact" => {
            let path_str = args
                .get("path")
                .or_else(|| args.get("archive_path"))
                .or_else(|| args.get("input_path"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' or 'archive_path' argument".to_string())?;
            let out_dir = args
                .get("output_directory")
                .and_then(|v| v.as_str())
                .map(Path::new);
            let policy = match args.get("integrity_policy").and_then(|v| v.as_str()) {
                Some("record-and-continue") => IntegrityPolicy::RecordAndContinue,
                _ => IntegrityPolicy::Fail,
            };
            let res = asar::extract_artifact(Path::new(path_str), out_dir, policy)
                .map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "recover_javascript_sources" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let out_dir_str = args
                .get("output_directory")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'output_directory' argument".to_string())?;
            let mode = match args.get("extraction_mode").and_then(|v| v.as_str()) {
                Some("heuristic") => ExtractionMode::Heuristic,
                Some("inspection") => ExtractionMode::Inspection,
                _ => ExtractionMode::Structural,
            };
            let rewrite = match args.get("rewrite_level").and_then(|v| v.as_str()) {
                Some("standard") => RewriteLevel::Standard,
                Some("aggressive") => RewriteLevel::Aggressive,
                _ => RewriteLevel::Minimal,
            };
            let res = SourceRecoverer::new(mode, rewrite)
                .recover(Path::new(path_str), Path::new(out_dir_str))
                .map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "compare_application_versions" | "diff_applications" => {
            let left_val = args
                .get("left")
                .or_else(|| args.get("left_path"))
                .or_else(|| args.get("source"))
                .ok_or_else(|| "Missing 'left' argument".to_string())?;
            let right_val = args
                .get("right")
                .or_else(|| args.get("right_path"))
                .or_else(|| args.get("target"))
                .ok_or_else(|| "Missing 'right' argument".to_string())?;
            let left_g = resolve_graph_value(left_val)?;
            let right_g = resolve_graph_value(right_val)?;
            let diff = ApplicationDiffer::compare_applications(&left_g, &right_g)?;
            serde_json::to_value(diff).map_err(|e| e.to_string())
        }
        "compare_source_to_bundle" => {
            let ref_val = args
                .get("reference")
                .or_else(|| args.get("left"))
                .or_else(|| args.get("source"))
                .ok_or_else(|| "Missing 'reference' argument".to_string())?;
            let app_val = args
                .get("application")
                .or_else(|| args.get("right"))
                .or_else(|| args.get("bundle"))
                .ok_or_else(|| "Missing 'application' argument".to_string())?;
            let ref_g = resolve_graph_value(ref_val)?;
            let app_g = resolve_graph_value(app_val)?;
            let diff = ApplicationDiffer::compare_applications(&ref_g, &app_g)?;
            serde_json::to_value(diff).map_err(|e| e.to_string())
        }
        "compare_javascript_export_shapes" => {
            let left_val = args
                .get("left")
                .ok_or_else(|| "Missing 'left' argument".to_string())?;
            let left_mod = args
                .get("left_module_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'left_module_path' argument".to_string())?;
            let left_exp = args
                .get("left_export_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'left_export_name' argument".to_string())?;
            let right_val = args
                .get("right")
                .ok_or_else(|| "Missing 'right' argument".to_string())?;
            let right_mod = args
                .get("right_module_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'right_module_path' argument".to_string())?;
            let right_exp = args
                .get("right_export_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'right_export_name' argument".to_string())?;
            let left_g = resolve_graph_value(left_val)?;
            let right_g = resolve_graph_value(right_val)?;
            let diff = ApplicationDiffer::compare_export_shapes(
                &left_g, left_mod, left_exp, &right_g, right_mod, right_exp,
            )?;
            serde_json::to_value(diff).map_err(|e| e.to_string())
        }
        "trace_application_feature" | "trace_feature" => {
            let app_val = args
                .get("application")
                .or_else(|| args.get("app"))
                .ok_or_else(|| "Missing 'application' argument".to_string())?;
            let seed: FeatureSeed =
                serde_json::from_value(args.get("seed").cloned().unwrap_or(Value::Null))
                    .map_err(|e| format!("Invalid 'seed' argument: {e}"))?;
            let direction = match args.get("direction").and_then(|v| v.as_str()) {
                Some("incoming") => TraceDirection::Incoming,
                Some("outgoing") => TraceDirection::Outgoing,
                _ => TraceDirection::Both,
            };
            let path = resolve_input_path(app_val)
                .ok_or_else(|| "Unable to resolve application path".to_string())?;
            let files = analyze_application_files(&path, 16_777_216).map_err(|e| e.to_string())?;
            let deps = graph::dependencies(&files);
            let tracer = ApplicationFeatureTracer::new(&files, &deps, None);
            let res = tracer.trace(&seed, direction);
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "trace_javascript_semantics" => {
            let app_val = args
                .get("application")
                .ok_or_else(|| "Missing 'application' argument".to_string())?;
            let query: SemanticQuery =
                serde_json::from_value(args.get("query").cloned().unwrap_or(Value::Null))
                    .map_err(|e| format!("Invalid 'query' argument: {e}"))?;
            let graph = if let Ok(g) =
                serde_json::from_value::<semantics::SemanticGraph>(app_val.clone())
            {
                if !g.nodes.is_empty() {
                    g
                } else if let Some(p) = resolve_input_path(app_val) {
                    build_application_semantic_graph(&p).map_err(|e| e.to_string())?
                } else {
                    return Err("Unable to resolve semantic graph".to_string());
                }
            } else if let Some(p) = resolve_input_path(app_val) {
                build_application_semantic_graph(&p).map_err(|e| e.to_string())?
            } else if let Some(s) = app_val.as_str() {
                semantics::build_semantic_graph(s, "inline.js")
            } else {
                return Err("Missing or invalid application argument".to_string());
            };
            let res = graph.trace(&query);
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "extract_sourcemap" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let out_dir_str = args
                .get("output_directory")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'output_directory' argument".to_string())?;
            let res = SourceMapExtractor::extract(Path::new(path_str), Path::new(out_dir_str))
                .map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "run_audit_pipeline" => {
            let target_str = args
                .get("target_path")
                .or_else(|| args.get("path"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'target_path' or 'path' argument".to_string())?;
            let out_dir = args
                .get("output_directory")
                .and_then(|v| v.as_str())
                .map(Path::new);
            let res =
                AuditPipeline::run(Path::new(target_str), out_dir).map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "pack_asar" => {
            let src_str = args
                .get("source_directory")
                .or_else(|| args.get("src"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'source_directory' argument".to_string())?;
            let out_str = args
                .get("output_path")
                .or_else(|| args.get("dest"))
                .or_else(|| args.get("output"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'output_path' argument".to_string())?;
            let report = asar::pack_asar(Path::new(src_str), Path::new(out_str))
                .map_err(|e| e.to_string())?;
            serde_json::to_value(report).map_err(|e| e.to_string())
        }
        "scan_secrets" => {
            if let Some(src) = args.get("source").and_then(|v| v.as_str()) {
                let file_path = args.get("path").and_then(|v| v.as_str());
                let res = SecretScanner::scan_str(src, file_path);
                serde_json::to_value(res).map_err(|e| e.to_string())
            } else if let Some(path_str) = args.get("path").and_then(|v| v.as_str()) {
                let path = Path::new(path_str);
                if path.is_file() {
                    let res = SecretScanner::scan_file(path).map_err(|e| e.to_string())?;
                    serde_json::to_value(res).map_err(|e| e.to_string())
                } else if path.is_dir() {
                    let files = collect_files(path).map_err(|e| e.to_string())?;
                    let mut all_res = crate::secrets::SecretScanResult::default();
                    for f in files {
                        if let Ok(res) = SecretScanner::scan_file(&f) {
                            all_res.secrets.extend(res.secrets);
                            all_res.endpoints.extend(res.endpoints);
                        }
                    }
                    all_res.total_secrets = all_res.secrets.len();
                    all_res.total_endpoints = all_res.endpoints.len();
                    if all_res.secrets.len() > 50 {
                        all_res.secrets.truncate(50);
                    }
                    if all_res.endpoints.len() > 50 {
                        all_res.endpoints.truncate(50);
                    }
                    serde_json::to_value(all_res).map_err(|e| e.to_string())
                } else {
                    Err(format!("Path not found: {path_str}"))
                }
            } else {
                Err("Missing either 'path' or 'source' argument".to_string())
            }
        }
        "audit_tauri" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let extract_to = args
                .get("output_directory")
                .and_then(|v| v.as_str())
                .map(Path::new);
            let res = TauriScanner::audit_path(Path::new(path_str), extract_to)
                .map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "inspect_binary_layout" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res =
                NativeInspector::inspect_layout(Path::new(path_str)).map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "inspect_go_binary" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res =
                NativeInspector::inspect_go(Path::new(path_str)).map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "inspect_rust_binary" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res =
                NativeInspector::inspect_rust(Path::new(path_str)).map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "inspect_wasm_artifact" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let bytes = std::fs::read(path_str).map_err(|e| e.to_string())?;
            let res = NativeInspector::inspect_wasm(&bytes);
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "inspect_android_package" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res =
                MobileInspector::inspect_apk(Path::new(path_str)).map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "inspect_sqlite_database" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = StoragePcapInspector::inspect_sqlite(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "inspect_packet_capture" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = StoragePcapInspector::inspect_pcap(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "inspect_artifact" => {
            let path_str = args
                .get("path")
                .or_else(|| args.get("artifact_path"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = NativeInspector::inspect_artifact(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "inspect_macho" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res =
                NativeInspector::inspect_macho(Path::new(path_str)).map_err(|e| e.to_string())?;
            Ok(res)
        }
        "list_architectures" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = NativeInspector::list_architectures(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "inspect_native_exports" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = NativeInspector::inspect_native_exports(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "inspect_byte_entropy" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let bytes = std::fs::read(path_str).map_err(|e| e.to_string())?;
            let chunk_size = args
                .get("chunk_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(4096) as usize;
            Ok(NativeInspector::inspect_byte_entropy(&bytes, chunk_size))
        }
        "compare_wasm_interfaces" => {
            let left_path = args
                .get("left_path")
                .or_else(|| args.get("left"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'left_path' argument".to_string())?;
            let right_path = args
                .get("right_path")
                .or_else(|| args.get("right"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'right_path' argument".to_string())?;
            let left_bytes = std::fs::read(left_path).map_err(|e| e.to_string())?;
            let right_bytes = std::fs::read(right_path).map_err(|e| e.to_string())?;
            Ok(NativeInspector::compare_wasm_interfaces(
                &left_bytes,
                &right_bytes,
            ))
        }
        "inspect_il2cpp_metadata" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = NativeInspector::inspect_il2cpp_metadata(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "identify_flutter_build" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = MobileInspector::identify_flutter_build(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "inspect_apk_signature" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = MobileInspector::inspect_apk_signature(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "project_android_application_graph" => {
            let path_str = args
                .get("path")
                .or_else(|| args.get("apk_path"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' or 'apk_path' argument".to_string())?;
            let res = MobileInspector::project_android_application_graph(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "trace_dylib_resolution" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let layout =
                NativeInspector::inspect_layout(Path::new(path_str)).map_err(|e| e.to_string())?;
            Ok(json!({
                "path": path_str,
                "format": layout.format,
                "total_imported_symbols": layout.imports.len(),
                "imports": layout.imports,
            }))
        }
        "inspect_signature" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let path = Path::new(path_str);
            if path_str.ends_with(".apk") {
                let res =
                    MobileInspector::inspect_apk_signature(path).map_err(|e| e.to_string())?;
                Ok(res)
            } else {
                let layout = NativeInspector::inspect_layout(path).map_err(|e| e.to_string())?;
                let has_code_sig = layout.sections.iter().any(|s| {
                    s.name.contains("signature")
                        || s.name.contains("SECURITY")
                        || s.name.contains("certificate")
                });
                Ok(json!({
                    "path": path_str,
                    "format": layout.format,
                    "has_signature_section": has_code_sig,
                    "sha256": layout.sha256,
                }))
            }
        }
        "list_strings" | "search_strings" => {
            let path_str = args
                .get("path")
                .or_else(|| args.get("file_path"))
                .and_then(|v| v.as_str());
            if let Some(path_str) = path_str {
                let bytes = std::fs::read(path_str).map_err(|e| e.to_string())?;
                let min_len = args.get("min_length").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
                let query = args
                    .get("query")
                    .or_else(|| args.get("filter"))
                    .and_then(|v| v.as_str());
                let mut strings = NativeInspector::list_strings(&bytes, min_len, 5000);
                if let Some(q) = query {
                    let q_lower = q.to_lowercase();
                    strings.retain(|s| s.to_lowercase().contains(&q_lower));
                }
                if strings.len() > limit {
                    strings.truncate(limit);
                }
                Ok(json!({
                    "path": path_str,
                    "total_found": strings.len(),
                    "strings": strings,
                }))
            } else {
                dispatch_extended_tool(name, args)
            }
        }
        "list_segments" => {
            let path_str = args.get("path").and_then(|v| v.as_str());
            if let Some(path_str) = path_str {
                let sections = NativeInspector::list_sections(Path::new(path_str))
                    .map_err(|e| e.to_string())?;
                Ok(json!({
                    "path": path_str,
                    "total_segments": sections.len(),
                    "segments": sections,
                }))
            } else {
                dispatch_extended_tool(name, args)
            }
        }
        "list_procedures" | "list_names" => {
            let path_str = args.get("path").and_then(|v| v.as_str());
            if let Some(path_str) = path_str {
                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
                let symbols = NativeInspector::list_symbols(Path::new(path_str), limit)
                    .map_err(|e| e.to_string())?;
                Ok(json!({
                    "path": path_str,
                    "total_symbols": symbols.len(),
                    "symbols": symbols,
                }))
            } else {
                dispatch_extended_tool(name, args)
            }
        }
        "inspect_model_artifact" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = NativeInspector::inspect_model_artifact(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "inspect_desktop_application" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = NativeInspector::inspect_desktop_application(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "inspect_python_pyc" => {
            let path_str = args
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' argument".to_string())?;
            let res = NativeInspector::inspect_python_pyc(Path::new(path_str))
                .map_err(|e| e.to_string())?;
            Ok(res)
        }
        "export_environment_bundle" => Ok(NativeInspector::export_environment_bundle()),
        "demangle_swift" => {
            let sym = args
                .get("symbol")
                .or_else(|| args.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let out = DynamicBridge::run_optional_bridge(
                "swift-demangle",
                "swift-demangle or xcode-select",
                &[sym],
                5,
            );
            if out["status"] == "success" {
                Ok(out)
            } else {
                Ok(json!({
                    "symbol": sym,
                    "demangled": sym,
                    "status": "raw"
                }))
            }
        }
        "list_browser_targets" => {
            let endpoint = args
                .get("cdp_endpoint")
                .or_else(|| args.get("endpoint"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:9222");
            let targets = DynamicBridge::query_cdp_targets(endpoint).map_err(|e| e.to_string())?;
            serde_json::to_value(targets).map_err(|e| e.to_string())
        }
        "list_electron_targets" => {
            let endpoint = args
                .get("cdp_endpoint")
                .or_else(|| args.get("endpoint"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:9222");
            let targets =
                DynamicBridge::list_electron_targets(endpoint).map_err(|e| e.to_string())?;
            serde_json::to_value(targets).map_err(|e| e.to_string())
        }
        "list_adb_devices" => {
            let devices = DynamicBridge::list_adb_devices().map_err(|e| e.to_string())?;
            serde_json::to_value(devices).map_err(|e| e.to_string())
        }
        "inspect_adb_device" => {
            let serial = args.get("serial").and_then(|v| v.as_str());
            let props = DynamicBridge::inspect_adb_device(serial).map_err(|e| e.to_string())?;
            serde_json::to_value(props).map_err(|e| e.to_string())
        }
        "list_adb_packages" => {
            let serial = args.get("serial").and_then(|v| v.as_str());
            let third_party = args
                .get("third_party_only")
                .and_then(|v| v.as_bool())
                .or_else(|| {
                    args.get("scope")
                        .and_then(|v| v.as_str())
                        .map(|s| s == "third_party")
                })
                .unwrap_or(false);
            let pkgs =
                DynamicBridge::list_adb_packages(serial, third_party).map_err(|e| e.to_string())?;
            serde_json::to_value(pkgs).map_err(|e| e.to_string())
        }
        "list_live_processes" => {
            let filter = args.get("filter").and_then(|v| v.as_str());
            let procs = DynamicBridge::list_live_processes(filter).map_err(|e| e.to_string())?;
            serde_json::to_value(procs).map_err(|e| e.to_string())
        }
        "inspect_live_process" => {
            let pid = args
                .get("pid")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "Missing 'pid' argument".to_string())? as u32;
            let detail = DynamicBridge::inspect_live_process(pid).map_err(|e| e.to_string())?;
            serde_json::to_value(detail).map_err(|e| e.to_string())
        }
        "execute_gdb" => {
            let args_vec = extract_args_list(args);
            let args_ref: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
            Ok(DynamicBridge::run_gdb(&args_ref))
        }
        "execute_frida" => {
            let args_vec = extract_args_list(args);
            let args_ref: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
            Ok(DynamicBridge::run_frida(&args_ref))
        }
        "inspect_with_objdump" => {
            let args_vec = extract_objdump_args(args);
            let args_ref: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
            Ok(DynamicBridge::run_objdump(&args_ref))
        }
        "execute_rizin" | "execute_rizin_command" => {
            let args_vec = extract_args_list(args);
            let args_ref: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
            Ok(DynamicBridge::run_rizin(&args_ref))
        }
        "decode_signal_sigrok" | "decode_signal_recording" => {
            let args_vec = extract_args_list(args);
            let args_ref: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
            Ok(DynamicBridge::run_sigrok(&args_ref))
        }
        "decompile_apktool_jadx" => {
            let args_vec = extract_args_list(args);
            let args_ref: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
            Ok(DynamicBridge::run_jadx_or_apktool(&args_ref))
        }

        // Evidence Ledger, DAG & Unknowns (src/evidence.rs)
        "get_evidence_bundle" => Ok(crate::evidence::get_evidence_bundle(args)),
        "export_evidence_bundle" => Ok(crate::evidence::export_evidence_bundle(args)),
        "import_evidence_bundle" => Ok(crate::evidence::import_evidence_bundle(args)),
        "record_unknown" => Ok(crate::evidence::record_unknown(args)),
        "update_unknown" => Ok(crate::evidence::update_unknown(args)),
        "list_unknowns" => Ok(crate::evidence::list_unknowns(args)),
        "verify_unknown_resolution" => Ok(crate::evidence::verify_unknown_resolution(args)),
        "inspect_analysis_view" => Ok(crate::evidence::inspect_analysis_view(args)),
        "compare_artifacts" => Ok(crate::evidence::compare_artifacts(args)),
        "compare_bundles" => Ok(crate::evidence::compare_bundles(args)),
        "build_reconstruction_obligation_ledger" => Ok(
            crate::evidence::build_reconstruction_obligation_ledger(args),
        ),
        "evaluate_reconstruction_coverage" => {
            Ok(crate::evidence::evaluate_reconstruction_coverage(args))
        }
        "verify_reconstruction" => Ok(crate::evidence::verify_reconstruction(args)),
        "build_call_path" => Ok(crate::evidence::build_call_path(args)),
        "compare_functions" => Ok(crate::evidence::compare_functions(args)),
        "find_changed_behavior" => Ok(crate::evidence::find_changed_behavior(args)),

        // Property Lists, Apple & Harmony Graphs (src/plist.rs)
        "inspect_plist" => Ok(crate::plist::inspect_plist(args)),
        "project_apple_application_graph" => {
            Ok(crate::plist::project_apple_application_graph(args))
        }
        "project_harmony_application_graph" => {
            Ok(crate::plist::project_harmony_application_graph(args))
        }
        "inspect_keyed_archive" => Ok(crate::plist::inspect_keyed_archive(args)),
        "decode_interface_builder" => Ok(crate::plist::decode_interface_builder(args)),

        // ECMA-335 .NET Managed & IL2CPP (src/managed.rs)
        "inspect_managed_artifact" => Ok(crate::managed::inspect_managed_artifact(args)),
        "inspect_managed_members" => Ok(crate::managed::inspect_managed_members(args)),
        "inspect_managed_native_boundaries" => {
            Ok(crate::managed::inspect_managed_native_boundaries(args))
        }
        "verify_managed_native_boundaries" => {
            Ok(crate::managed::verify_managed_native_boundaries(args))
        }
        "compare_managed_members" => Ok(crate::managed::compare_managed_members(args)),
        "project_managed_application_graph" => {
            Ok(crate::managed::project_managed_application_graph(args))
        }
        "import_managed_reconstruction" => Ok(crate::managed::import_managed_reconstruction(args)),

        // Stateful Debugger Sessions: GDB, Rizin, Frida (src/session_manager.rs)
        "start_gdb_session" => Ok(crate::session_manager::start_gdb_session(args)),
        "gdb_console" => Ok(crate::session_manager::gdb_console(args)),
        "gdb_session_status" => Ok(crate::session_manager::gdb_session_status(args)),
        "close_gdb_session" => Ok(crate::session_manager::close_gdb_session(args)),
        "start_rizin_debug_session" => Ok(crate::session_manager::start_rizin_debug_session(args)),
        "rizin_debug_command" => Ok(crate::session_manager::rizin_debug_command(args)),
        "rizin_debug_session_status" => {
            Ok(crate::session_manager::rizin_debug_session_status(args))
        }
        "close_rizin_debug_session" => Ok(crate::session_manager::close_rizin_debug_session(args)),
        "start_frida_session" => Ok(crate::session_manager::start_frida_session(args)),
        "frida_session_status" => Ok(crate::session_manager::frida_session_status(args)),
        "load_frida_script" => Ok(crate::session_manager::load_frida_script(args)),
        "unload_frida_script" => Ok(crate::session_manager::unload_frida_script(args)),
        "resume_frida_session" => Ok(crate::session_manager::resume_frida_session(args)),
        "close_frida_session" => Ok(crate::session_manager::close_frida_session(args)),

        // CDP Web Inspection & Dynamic Runtime (src/cdp.rs)
        "inspect_web_page" => Ok(crate::cdp::inspect_web_page(args)),
        "inspect_electron_page" => Ok(crate::cdp::inspect_electron_page(args)),
        "inspect_web_event_listeners" => Ok(crate::cdp::inspect_web_event_listeners(args)),
        "discover_webmcp_tools" => Ok(crate::cdp::discover_webmcp_tools(args)),
        "observe_web_session" => Ok(crate::cdp::observe_web_session(args)),
        "observe_web_execution" => Ok(crate::cdp::observe_web_execution(args)),
        "capture_web_screenshot" => Ok(crate::cdp::capture_web_screenshot(args)),
        "evaluate_web_script" => Ok(crate::cdp::evaluate_web_script(args)),
        "export_web_scripts" => Ok(crate::cdp::export_web_scripts(args)),
        "trace_web_module_imports" => Ok(crate::cdp::trace_web_module_imports(args)),
        "trace_web_source_location" => Ok(crate::cdp::trace_web_source_location(args)),
        "compare_web_captures" => Ok(crate::cdp::compare_web_captures(args)),
        "compare_web_screenshots" => Ok(crate::cdp::compare_web_screenshots(args)),
        "analyze_web_bundle" => Ok(crate::cdp::analyze_web_bundle(args)),

        _ => dispatch_extended_tool(name, args),
    }
}

fn is_hopper_tool(name: &str) -> bool {
    matches!(
        name,
        "current_address"
            | "current_document"
            | "current_procedure"
            | "goto_address"
            | "list_documents"
            | "list_bookmarks"
            | "set_bookmark"
            | "unset_bookmark"
            | "comment"
            | "set_comment"
            | "inline_comment"
            | "set_inline_comment"
            | "set_address_name"
            | "set_addresses_names"
            | "address_name"
            | "address_to_file_offset"
            | "next_address"
            | "prev_address"
            | "inspect_address_context"
    )
}

fn is_ghidra_tool(name: &str) -> bool {
    matches!(
        name,
        "open_binary"
            | "close_binary"
            | "analyze_function"
            | "binary_overview"
            | "binary_session"
            | "procedure_assembly"
            | "procedure_pseudo_code"
            | "procedure_info"
            | "procedure_references"
            | "procedure_callers"
            | "procedure_callees"
            | "procedure_address"
            | "read_function_instructions"
            | "read_bytes"
            | "search_bytes"
            | "search_procedures"
            | "search_strings"
            | "xrefs"
            | "find_xrefs_to_name"
            | "get_call_graph"
            | "trace_call_path"
            | "resolve_containing_procedure"
            | "resolve_native_call_targets"
            | "inspect_native_instruction"
            | "inspect_native_api"
            | "inspect_native_data_type"
            | "inspect_native_dispatch_metadata"
            | "inspect_native_load_image"
            | "annotate_native_function"
            | "batch_decompile"
            | "trace_native_values"
            | "trace_native_ui_action"
    )
}

fn handle_adb_tool(name: &str, args: &Value) -> Result<Value, String> {
    let serial = args.get("serial").and_then(|v| v.as_str());
    let mut adb_args: Vec<String> = Vec::new();
    if let Some(s) = serial {
        adb_args.push("-s".to_string());
        adb_args.push(s.to_string());
    }

    match name {
        "list_adb_processes" => {
            adb_args.extend(["shell".to_string(), "ps".to_string(), "-A".to_string()]);
        }
        "list_adb_features" => {
            adb_args.extend([
                "shell".to_string(),
                "pm".to_string(),
                "list".to_string(),
                "features".to_string(),
            ]);
        }
        "list_adb_services" => {
            adb_args.extend([
                "shell".to_string(),
                "service".to_string(),
                "list".to_string(),
            ]);
        }
        "list_adb_directory" => {
            let path = args
                .get("device_path")
                .and_then(|v| v.as_str())
                .unwrap_or("/");
            adb_args.extend([
                "shell".to_string(),
                "ls".to_string(),
                "-la".to_string(),
                path.to_string(),
            ]);
        }
        "inspect_adb_package" => {
            let pkg = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            adb_args.extend([
                "shell".to_string(),
                "dumpsys".to_string(),
                "package".to_string(),
                pkg.to_string(),
            ]);
        }
        "inspect_adb_display" => {
            adb_args.extend(["shell".to_string(), "wm".to_string(), "size".to_string()]);
        }
        "inspect_adb_window" => {
            adb_args.extend([
                "shell".to_string(),
                "dumpsys".to_string(),
                "window".to_string(),
                "windows".to_string(),
            ]);
        }
        "read_adb_logcat" => {
            adb_args.extend(["logcat".to_string(), "-d".to_string(), "-t".to_string()]);
            let lines = args.get("count").and_then(|v| v.as_u64()).unwrap_or(200);
            adb_args.push(lines.to_string());
        }
        "read_adb_setting" => {
            let ns = args
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("system");
            let key = args.get("key").and_then(|v| v.as_str()).unwrap_or("");
            adb_args.extend([
                "shell".to_string(),
                "settings".to_string(),
                "get".to_string(),
                ns.to_string(),
                key.to_string(),
            ]);
        }
        "resolve_adb_packages" => {
            let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            adb_args.extend([
                "shell".to_string(),
                "pm".to_string(),
                "list".to_string(),
                "packages".to_string(),
                q.to_string(),
            ]);
        }
        "pull_adb_file" => {
            let dev_path = args
                .get("device_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let out_dir = args
                .get("output_directory")
                .and_then(|v| v.as_str())
                .unwrap_or(".");
            adb_args.extend([
                "pull".to_string(),
                dev_path.to_string(),
                out_dir.to_string(),
            ]);
        }
        "push_adb_file" => {
            let local_path = args
                .get("local_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let dev_path = args
                .get("device_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            adb_args.extend([
                "push".to_string(),
                local_path.to_string(),
                dev_path.to_string(),
            ]);
        }
        "start_adb_activity" => {
            let action = args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("android.intent.action.VIEW");
            adb_args.extend([
                "shell".to_string(),
                "am".to_string(),
                "start".to_string(),
                "-W".to_string(),
                "-a".to_string(),
                action.to_string(),
            ]);
            if let Some(uri) = args.get("data_uri").and_then(|v| v.as_str()) {
                adb_args.extend(["-d".to_string(), uri.to_string()]);
            }
        }
        "start_adb_app" => {
            let pkg = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            adb_args.extend([
                "shell".to_string(),
                "monkey".to_string(),
                "-p".to_string(),
                pkg.to_string(),
                "-c".to_string(),
                "android.intent.category.LAUNCHER".to_string(),
                "1".to_string(),
            ]);
        }
        "stop_adb_app" => {
            let pkg = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            adb_args.extend([
                "shell".to_string(),
                "am".to_string(),
                "force-stop".to_string(),
                pkg.to_string(),
            ]);
        }
        "install_adb_package" => {
            let apk = args.get("apk_path").and_then(|v| v.as_str()).unwrap_or("");
            let replace = args
                .get("replace")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if replace {
                adb_args.extend(["install".to_string(), "-r".to_string(), apk.to_string()]);
            } else {
                adb_args.extend(["install".to_string(), apk.to_string()]);
            }
        }
        "uninstall_adb_package" => {
            let pkg = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            adb_args.extend(["uninstall".to_string(), pkg.to_string()]);
        }
        "collect_adb_bugreport" => {
            let out_dir = args
                .get("output_directory")
                .and_then(|v| v.as_str())
                .unwrap_or(".");
            adb_args.extend(["bugreport".to_string(), out_dir.to_string()]);
        }
        "capture_adb_screen" => {
            adb_args.extend([
                "exec-out".to_string(),
                "screencap".to_string(),
                "-p".to_string(),
            ]);
        }
        "inspect_adb_client" => {
            adb_args.push("version".to_string());
        }
        "pull_adb_package" => {
            let pkg = args.get("package").and_then(|v| v.as_str()).unwrap_or("");
            adb_args.extend([
                "shell".to_string(),
                "pm".to_string(),
                "path".to_string(),
                pkg.to_string(),
            ]);
        }
        _ => {
            return Ok(crate::tcp_driver::unavailable_engine_response(
                "ADB Driver",
                name,
                "Tool not mapped or unsupported by local adb bridge.",
                "inspect_android_package",
            ));
        }
    }

    let refs: Vec<&str> = adb_args.iter().map(|s| s.as_str()).collect();
    Ok(DynamicBridge::run_optional_bridge(
        "adb",
        "apt install adb || brew install android-platform-tools",
        &refs,
        15,
    ))
}

fn dispatch_extended_tool(name: &str, args: &Value) -> Result<Value, String> {
    if !crate::catalog::has_tool(name) {
        return Err(format!("Unknown tool: {name}"));
    }

    if name.contains("_adb_")
        || name.ends_with("_adb_screen")
        || name.starts_with("resolve_adb_")
        || name.starts_with("collect_adb_")
    {
        return handle_adb_tool(name, args);
    }

    if name.contains("_jeb_") {
        return Ok(crate::tcp_driver::call_jeb_mcp(name, args));
    }

    if is_hopper_tool(name) {
        return Ok(crate::tcp_driver::unavailable_engine_response(
            "Hopper Disassembler v4/v5",
            name,
            "Launch Hopper GUI with Python REA bridge plugin listening on localhost.",
            "inspect_binary_layout",
        ));
    }

    if is_ghidra_tool(name) {
        return Ok(crate::tcp_driver::unavailable_engine_response(
            "Ghidra Headless Analyzer",
            name,
            "Install Ghidra and configure GHIDRA_INSTALL_DIR, or launch Ghidra Bridge.",
            "inspect_binary_layout",
        ));
    }

    if name.contains("cutter") || name.contains("rizin_debug") {
        return Ok(crate::tcp_driver::unavailable_engine_response(
            "Cutter / Rizin Interactive Session",
            name,
            "Launch Cutter with REA bridge or start Rizin debug session.",
            "execute_rizin",
        ));
    }

    if name.contains("frida_session")
        || name.contains("frida_script")
        || name.contains("frida_devices")
        || name.contains("frida_processes")
    {
        return Ok(crate::tcp_driver::unavailable_engine_response(
            "Frida Server / Session Daemon",
            name,
            "Start frida-server on target device or localhost.",
            "execute_frida",
        ));
    }

    if name.contains("gdb_session") || name == "gdb_console" {
        return Ok(crate::tcp_driver::unavailable_engine_response(
            "GDB MI Session Daemon",
            name,
            "GDB persistent MI daemon is required for stateful debugging.",
            "execute_gdb",
        ));
    }

    if name.starts_with("observe_web_")
        || name.starts_with("capture_web_")
        || name.starts_with("capture_browser_")
        || name.starts_with("discover_webmcp_")
    {
        return Ok(crate::tcp_driver::unavailable_engine_response(
            "Chrome DevTools Protocol (CDP)",
            name,
            "Launch Chromium with --remote-debugging-port=9222.",
            "list_browser_targets",
        ));
    }

    Ok(crate::tcp_driver::unavailable_engine_response(
        "REA Extended Engine",
        name,
        "Proprietary engine or specific environment driver offline.",
        "inspect_binary_layout",
    ))
}

fn extract_objdump_args(args: &Value) -> Vec<String> {
    if let Some(arr) = args.get("args").and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
    }
    let mut result = Vec::new();
    if let Some(op) = args.get("operation").and_then(|v| v.as_str()) {
        match op {
            "file_headers" => result.push("-f".to_string()),
            "section_headers" => result.push("-h".to_string()),
            "symbols" => result.push("-t".to_string()),
            "relocations" => result.push("-r".to_string()),
            "dwarf" => result.push("-W".to_string()),
            "disassemble" => result.push("-d".to_string()),
            "disassemble_all" => result.push("-D".to_string()),
            _ => result.push("-x".to_string()),
        }
    }
    if let Some(true) = args.get("follow_debug_links").and_then(|v| v.as_bool()) {
        result.push("-P".to_string());
    }
    if let Some(path) = args.get("path").and_then(|v| v.as_str()) {
        result.push(path.to_string());
    }
    if result.is_empty() {
        extract_args_list(args)
    } else {
        result
    }
}

fn extract_args_list(args: &Value) -> Vec<String> {
    if let Some(arr) = args.get("args").and_then(|v| v.as_array()) {
        arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    } else if let Some(s) = args
        .get("command")
        .or_else(|| args.get("path"))
        .and_then(|v| v.as_str())
    {
        vec![s.to_string()]
    } else {
        Vec::new()
    }
}

/// Bound stdio JSON-RPC memory even if a client never sends a newline.
/// Large artifacts should be supplied by path rather than inlined in MCP.
const MAX_MCP_REQUEST_BYTES: usize = 64 * 1024 * 1024;

enum BoundedLine {
    Line(Vec<u8>),
    Oversize,
}

fn read_bounded_line<R: BufRead>(reader: &mut R, limit: usize) -> io::Result<Option<BoundedLine>> {
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(if oversized {
                Some(BoundedLine::Oversize)
            } else if line.is_empty() {
                None
            } else {
                Some(BoundedLine::Line(line))
            });
        }

        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let data_len = newline.unwrap_or(buffer.len());
        if !oversized {
            if data_len > limit.saturating_sub(line.len()) {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(&buffer[..data_len]);
            }
        }
        reader.consume(data_len + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(if oversized {
                BoundedLine::Oversize
            } else {
                BoundedLine::Line(line)
            }));
        }
    }
}

pub fn run_mcp_server() -> Result<(), Box<dyn Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut input = stdin.lock();

    loop {
        let line = match read_bounded_line(&mut input, MAX_MCP_REQUEST_BYTES) {
            Ok(Some(BoundedLine::Line(line))) => line,
            Ok(Some(BoundedLine::Oversize)) => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {"code": -32600, "message": "MCP request exceeds 64 MiB input limit"}
                });
                writeln!(stdout, "{}", serde_json::to_string(&err)?)?;
                stdout.flush()?;
                continue;
            }
            Ok(None) => break,
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(e.into()),
        };
        let trimmed = match std::str::from_utf8(&line) {
            Ok(text) => text.trim(),
            Err(_) => {
                let err = json!({
                    "jsonrpc": "2.0", "id": Value::Null,
                    "error": {"code": -32700, "message": "Invalid UTF-8 JSON request"}
                });
                writeln!(stdout, "{}", serde_json::to_string(&err)?)?;
                stdout.flush()?;
                continue;
            }
        };
        if trimmed.is_empty() {
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(_) => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": -32700,
                        "message": "Parse error"
                    }
                });
                writeln!(stdout, "{}", serde_json::to_string(&err)?)?;
                stdout.flush()?;
                continue;
            }
        };

        // JSON-RPC 2.0 §4.1: Notifications have no id and must not receive a response
        let id = match req.id {
            Some(i) => i,
            None => continue,
        };

        match req.method.as_str() {
            "initialize" => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "rea-fast",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }
                });
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
            "notifications/initialized" => {
                // Notifications do not receive responses
            }
            "ping" => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {}
                });
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
            "tools/list" => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": tool_list()
                });
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
            "tools/call" => {
                let params = req.params.unwrap_or(Value::Null);
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params.get("arguments").unwrap_or(&Value::Null);

                let res = handle_tool_call(tool_name, arguments);
                let tool_result = match res {
                    Ok(val) => ToolResult {
                        content: vec![ToolContent {
                            content_type: "text",
                            text: serde_json::to_string_pretty(&val).unwrap_or_default(),
                        }],
                        is_error: false,
                    },
                    Err(err_msg) => ToolResult {
                        content: vec![ToolContent {
                            content_type: "text",
                            text: err_msg,
                        }],
                        is_error: true,
                    },
                };

                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": tool_result
                });
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
            _ => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", req.method)
                    }
                });
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_mcp_line_is_drained_without_losing_following_request() {
        let valid = br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;
        let mut input = vec![b'x'; 100];
        input.push(b'\n');
        input.extend_from_slice(valid);
        input.push(b'\n');
        let mut reader = io::BufReader::with_capacity(7, io::Cursor::new(input));
        assert!(matches!(
            read_bounded_line(&mut reader, 64).unwrap(),
            Some(BoundedLine::Oversize)
        ));
        match read_bounded_line(&mut reader, 64).unwrap() {
            Some(BoundedLine::Line(bytes)) => assert_eq!(bytes, valid),
            _ => panic!("Next JSON-RPC request must remain intact"),
        }
        assert!(read_bounded_line(&mut reader, 64).unwrap().is_none());

        let mut eof = io::Cursor::new(vec![b'x'; 100]);
        assert!(matches!(
            read_bounded_line(&mut eof, 64).unwrap(),
            Some(BoundedLine::Oversize)
        ));
    }

    #[test]
    fn meta_tool_refuses_recursive_calls_without_crashing_server() {
        let result = handle_tool_call(
            "rea_execute_tool",
            &json!({"tool_name": "rea_execute_tool", "arguments": {"tool_name": "rea_execute_tool"}}),
        );
        assert!(result.unwrap_err().contains("cannot invoke itself"));
    }

    #[test]
    fn meta_tool_validates_target_and_argument_shape() {
        assert!(
            handle_tool_call("rea_execute_tool", &json!({"tool_name": "no_such_tool"})).is_err()
        );
        assert!(
            handle_tool_call(
                "rea_execute_tool",
                &json!({"tool_name": "scan_secrets", "arguments": []})
            )
            .is_err()
        );
    }

    #[test]
    fn tool_list_contains_expected_tools() {
        let tools = tool_list();
        let list = tools["tools"].as_array().unwrap();
        let names: Vec<_> = list.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(
            list.len() >= 35,
            "Expected at least 35 core tools in catalog"
        );
        assert!(names.contains(&"inspect_electron_fuses"));
        assert!(names.contains(&"analyze_javascript_application"));
        assert!(names.contains(&"inspect_asar"));
        assert!(names.contains(&"analyze_electron_source"));
        assert!(names.contains(&"extract_artifact"));
        assert!(names.contains(&"recover_javascript_sources"));
        assert!(names.contains(&"compare_application_versions"));
        assert!(names.contains(&"compare_javascript_export_shapes"));
        assert!(names.contains(&"trace_application_feature"));
        assert!(names.contains(&"trace_javascript_semantics"));
        assert!(names.contains(&"extract_sourcemap"));
        assert!(names.contains(&"run_audit_pipeline"));
        assert!(names.contains(&"pack_asar"));
        assert!(names.contains(&"scan_secrets"));
        assert!(names.contains(&"audit_tauri"));
        assert!(names.contains(&"inspect_binary_layout"));
        assert!(names.contains(&"inspect_go_binary"));
        assert!(names.contains(&"inspect_rust_binary"));
        assert!(names.contains(&"inspect_wasm_artifact"));
        assert!(names.contains(&"inspect_android_package"));
        assert!(names.contains(&"inspect_sqlite_database"));
        assert!(names.contains(&"inspect_packet_capture"));
        assert!(names.contains(&"list_browser_targets"));
        assert!(names.contains(&"list_electron_targets"));
        assert!(names.contains(&"list_adb_devices"));
        assert!(names.contains(&"inspect_adb_device"));
        assert!(names.contains(&"list_adb_packages"));
        assert!(names.contains(&"list_live_processes"));
        assert!(names.contains(&"inspect_live_process"));
        assert!(names.contains(&"execute_gdb"));
        assert!(names.contains(&"execute_frida"));
        assert!(names.contains(&"inspect_with_objdump"));
        assert!(names.contains(&"execute_rizin"));
        assert!(names.contains(&"decode_signal_sigrok"));
        assert!(names.contains(&"decompile_apktool_jadx"));
    }

    #[test]
    fn test_full_catalog_profile() {
        set_profile_full(true);
        let tools = tool_list();
        let list = tools["tools"].as_array().unwrap();
        assert_eq!(
            list.len(),
            245,
            "Expected exactly 245 tools in full catalog"
        );
        set_profile_full(false);
    }

    #[test]
    fn test_rea_search_and_execute_tools() {
        let search_args = json!({ "query": "electron" });
        let search_res = handle_tool_call("rea_search_tools", &search_args).unwrap();
        assert!(search_res["count"].as_u64().unwrap() > 0);
        assert_eq!(
            search_res["capability_counts"]["native"].as_u64().unwrap()
                + search_res["capability_counts"]["external-provider"]
                    .as_u64()
                    .unwrap()
                + search_res["capability_counts"]["unavailable"]
                    .as_u64()
                    .unwrap(),
            search_res["count"].as_u64().unwrap()
        );
        assert!(
            search_res["tools"]
                .as_array()
                .unwrap()
                .iter()
                .all(|tool| { tool["rea_fast_capability"]["upstream_parity"] == "not_verified" })
        );

        let exec_args = json!({
            "tool_name": "rea_search_tools",
            "arguments": { "query": "fuses" }
        });
        let exec_res = handle_tool_call("rea_execute_tool", &exec_args).unwrap();
        assert!(exec_res["count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn handles_electron_source_tool_call() {
        let args = json!({
            "path": "test.js",
            "source": "const { ipcRenderer } = require('electron'); ipcRenderer.send('ping', 'data');"
        });
        let res = handle_tool_call("analyze_electron_source", &args).unwrap();
        assert_eq!(res["ipc"].as_array().unwrap().len(), 1);
        assert_eq!(res["ipc"][0]["channel"], "ping");
    }

    #[test]
    fn handles_trace_javascript_semantics_tool_call() {
        let args = json!({
            "application": "const x = 42; function foo() { return x; } foo();",
            "query": {
                "seed": {
                    "kind": "semantic-node",
                    "node_id": "inline.js:foo"
                },
                "direction": "backward-provenance"
            }
        });
        let res = handle_tool_call("trace_javascript_semantics", &args).unwrap();
        assert!(res.get("paths").is_some());
    }

    #[test]
    fn handles_compare_application_versions_tool_call() {
        let left = json!({
            "modules": [{ "path": "index.js", "bytes": 10, "lines": 1, "exports": ["init"] }],
            "edges": []
        });
        let right = json!({
            "modules": [{ "path": "index.js", "bytes": 20, "lines": 2, "exports": ["init", "start"] }],
            "edges": []
        });
        let args = json!({
            "left": left,
            "right": right
        });
        let res = handle_tool_call("compare_application_versions", &args).unwrap();
        assert_eq!(res["changed_modules"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn handles_compare_javascript_export_shapes_tool_call() {
        let left = json!({
            "modules": [{ "path": "lib.js", "bytes": 10, "lines": 1, "exports": ["foo"] }],
            "edges": []
        });
        let right = json!({
            "modules": [{ "path": "lib.js", "bytes": 20, "lines": 2, "exports": ["foo"] }],
            "edges": []
        });
        let args = json!({
            "left": left,
            "left_module_path": "lib.js",
            "left_export_name": "foo",
            "right": right,
            "right_module_path": "lib.js",
            "right_export_name": "foo"
        });
        let res = handle_tool_call("compare_javascript_export_shapes", &args).unwrap();
        assert_eq!(res["left_export"], "foo");
        assert_eq!(res["status"], "unchanged");
    }

    fn make_test_asar_bytes(json: &str, content: &[u8]) -> Vec<u8> {
        let text = json.as_bytes();
        let aligned_json = text.len().div_ceil(4) * 4;
        let header_size = (8 + aligned_json) as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&header_size.to_le_bytes());
        bytes.extend_from_slice(&(header_size - 4).to_le_bytes());
        bytes.extend_from_slice(&(text.len() as u32).to_le_bytes());
        bytes.extend_from_slice(text);
        while bytes.len() < (8 + header_size) as usize {
            bytes.push(0);
        }
        bytes.extend_from_slice(content);
        bytes
    }

    #[test]
    fn handles_inspect_electron_fuses_tool_call() {
        let mut binary = vec![0u8; 512];
        binary[0..4].copy_from_slice(b"\x7fELF");
        binary[64..96].copy_from_slice(b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX");
        binary[96] = 1; // version
        binary[97] = 9; // fuse count
        binary[98..107].copy_from_slice(&[1, 1, 0, 1, 1, 0, 1, 0, 1]);

        let temp_path = std::env::temp_dir().join(format!("test_fuses_{}.bin", std::process::id()));
        std::fs::write(&temp_path, &binary).unwrap();

        let args = json!({ "path": temp_path.to_string_lossy() });
        let res = handle_tool_call("inspect_electron_fuses", &args).unwrap();
        assert_eq!(res["slices"][0]["wire_version"], 1);
        assert_eq!(res["slices"][0]["fuses"].as_array().unwrap().len(), 9);

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn handles_inspect_asar_and_extract_tool_calls() {
        let json = r#"{"files":{"main.js":{"size":13,"offset":"0"}}}"#;
        let content = b"console.log()";
        let asar_bytes = make_test_asar_bytes(json, content);

        let temp_asar = std::env::temp_dir().join(format!("test_mcp_{}.asar", std::process::id()));
        std::fs::write(&temp_asar, &asar_bytes).unwrap();

        // 1. inspect_asar
        let inspect_args = json!({ "path": temp_asar.to_string_lossy() });
        let inspect_res = handle_tool_call("inspect_asar", &inspect_args).unwrap();
        assert_eq!(inspect_res["total_entries"], 1);
        assert_eq!(inspect_res["entries"][0]["path"], "main.js");

        // 2. extract_artifact
        let out_dir = std::env::temp_dir().join(format!("test_mcp_extract_{}", std::process::id()));
        let extract_args = json!({
            "path": temp_asar.to_string_lossy(),
            "output_directory": out_dir.to_string_lossy(),
            "integrity_policy": "fail"
        });
        let extract_res = handle_tool_call("extract_artifact", &extract_args).unwrap();
        assert_eq!(extract_res["total_files"], 1);
        assert_eq!(
            std::fs::read(out_dir.join("main.js")).unwrap(),
            b"console.log()"
        );

        let _ = std::fs::remove_file(temp_asar);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn handles_recover_javascript_sources_tool_call() {
        let bundle_code = r#"
            (self["webpackChunk"] = self["webpackChunk"] || []).push([["main"], {
                "./src/app.js": (function(module, exports, __webpack_require__) {
                    console.log("recovered app");
                })
            }]);
        "#;
        let bundle_file =
            std::env::temp_dir().join(format!("test_bundle_{}.js", std::process::id()));
        let out_dir = std::env::temp_dir().join(format!("test_recover_{}", std::process::id()));
        std::fs::write(&bundle_file, bundle_code).unwrap();

        let args = json!({
            "path": bundle_file.to_string_lossy(),
            "output_directory": out_dir.to_string_lossy(),
            "extraction_mode": "structural",
            "rewrite_level": "standard"
        });
        let res = handle_tool_call("recover_javascript_sources", &args).unwrap();
        assert!(!res["recovered_modules"].as_array().unwrap().is_empty());
        assert!(out_dir.join("src/app.js").exists());

        let _ = std::fs::remove_file(bundle_file);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn handles_analyze_javascript_application_and_trace_feature_tool_calls() {
        let app_dir = std::env::temp_dir().join(format!("test_app_{}", std::process::id()));
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::write(
            app_dir.join("index.js"),
            "import { auth } from './auth.js'; auth();",
        )
        .unwrap();
        std::fs::write(
            app_dir.join("auth.js"),
            "export function auth() { return 'secret_token'; }",
        )
        .unwrap();

        // 1. analyze_javascript_application
        let analyze_args = json!({ "input_path": app_dir.to_string_lossy() });
        let graph_res = handle_tool_call("analyze_javascript_application", &analyze_args).unwrap();
        assert!(graph_res["nodes"].as_array().unwrap().len() >= 2);

        // 2. trace_application_feature
        let trace_args = json!({
            "application": app_dir.to_string_lossy(),
            "seed": {
                "kind": "string",
                "value": "auth",
                "match": "contains",
                "case_sensitive": true
            },
            "direction": "both"
        });
        let trace_res = handle_tool_call("trace_application_feature", &trace_args).unwrap();
        let visited = trace_res["visited_modules"].as_array().unwrap();
        assert!(
            visited
                .iter()
                .any(|v| v.as_str().unwrap().contains("auth.js"))
        );

        let _ = std::fs::remove_dir_all(app_dir);
    }

    #[test]
    fn handles_extended_jeb_tool_diagnostic() {
        let args = json!({
            "item_address": "com.example.MainActivity",
            "item_kind": "type"
        });
        let res = handle_tool_call("decompile_jeb_item", &args).unwrap();
        assert_eq!(res["status"], "unavailable");
        assert_eq!(res["engine"], "JEB Decompiler MCP Server");
        assert!(!res["recommended_fallback"].is_null());
    }

    #[test]
    fn handles_extended_ghidra_tool_diagnostic() {
        let args = json!({
            "procedure": "main"
        });
        let res = handle_tool_call("analyze_function", &args).unwrap();
        assert_eq!(res["status"], "unavailable");
        assert_eq!(res["engine"], "Ghidra Headless Analyzer");
        assert_eq!(res["recommended_fallback"], "inspect_binary_layout");
    }

    #[test]
    fn handles_unknown_tool_call_error() {
        let args = json!({});
        let err = handle_tool_call("non_existent_tool_12345", &args).unwrap_err();
        assert!(err.contains("Unknown tool"));
    }

    #[test]
    fn test_extract_objdump_args_mapping() {
        let args = json!({
            "operation": "disassemble",
            "path": "/bin/ls",
            "follow_debug_links": true
        });
        let mapped = extract_objdump_args(&args);
        assert_eq!(mapped, vec!["-d", "-P", "/bin/ls"]);
    }

    #[test]
    fn test_tool_aliases_execute() {
        let rizin_args = json!({ "command": "-v" });
        let res = handle_tool_call("execute_rizin_command", &rizin_args);
        assert!(res.is_ok());

        let sigrok_args = json!({ "args": ["-V"] });
        let res_sig = handle_tool_call("decode_signal_recording", &sigrok_args);
        assert!(res_sig.is_ok());
    }

    #[test]
    fn test_unmapped_adb_tool_fallback() {
        let args = json!({});
        let res = handle_adb_tool("unmapped_adb_action", &args).unwrap();
        assert_eq!(res["status"], "unavailable");
        assert_eq!(res["engine"], "ADB Driver");
    }

    #[test]
    fn test_evidence_tools_dispatch() {
        let bundle =
            handle_tool_call("get_evidence_bundle", &json!({ "detail": "summary" })).unwrap();
        assert_eq!(bundle["status"], "complete");

        let rec_args = json!({
            "question": "Where is the cryptographic key generated?",
            "domain": "security"
        });
        let unk = handle_tool_call("record_unknown", &rec_args).unwrap();
        assert_eq!(unk["status"], "open");

        let list = handle_tool_call("list_unknowns", &json!({})).unwrap();
        assert!(list["total"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_plist_and_apple_graph_tools_dispatch() {
        let plist_res = handle_tool_call(
            "inspect_plist",
            &json!({ "path": "/nonexistent/test.plist" }),
        )
        .unwrap();
        assert_eq!(plist_res["status"], "error");

        let apple_graph = handle_tool_call(
            "project_apple_application_graph",
            &json!({ "inventory_evidence": [] }),
        )
        .unwrap();
        assert_eq!(apple_graph["status"], "complete");
    }

    #[test]
    fn test_managed_and_debugger_tools_dispatch() {
        let mg = handle_tool_call(
            "inspect_managed_artifact",
            &json!({ "path": "/nonexistent/test.dll" }),
        )
        .unwrap();
        assert_eq!(mg["status"], "error");

        let gdb_status =
            handle_tool_call("gdb_session_status", &json!({ "session_id": "test_sess" })).unwrap();
        assert_eq!(gdb_status["status"], "closed");
    }

    #[test]
    fn test_new_extended_native_tools_dispatch() {
        // 1. diff_applications alias
        let left = json!({
            "modules": [{ "path": "a.js", "bytes": 10, "lines": 1, "exports": ["init"] }],
            "edges": []
        });
        let right = json!({
            "modules": [{ "path": "a.js", "bytes": 20, "lines": 2, "exports": ["init", "run"] }],
            "edges": []
        });
        let diff_res = handle_tool_call(
            "diff_applications",
            &json!({ "left": left, "right": right }),
        )
        .unwrap();
        assert_eq!(diff_res["changed_modules"].as_array().unwrap().len(), 1);

        // 2. compare_source_to_bundle
        let compare_res = handle_tool_call(
            "compare_source_to_bundle",
            &json!({ "reference": left, "application": right }),
        )
        .unwrap();
        assert_eq!(compare_res["changed_modules"].as_array().unwrap().len(), 1);

        // 3. export_environment_bundle
        let env_res = handle_tool_call("export_environment_bundle", &json!({})).unwrap();
        assert_eq!(env_res["backend"], "rea-fast (native zero-dependency)");
        assert_eq!(env_res["status"], "ready");

        // 4. inspect_byte_entropy & list_strings on temp file
        let temp_bin =
            std::env::temp_dir().join(format!("test_entropy_{}.bin", std::process::id()));
        std::fs::write(
            &temp_bin,
            b"HELLO_WORLD_SECRET_KEY_1234567890\n\x00\x00\x00\xff\xfe",
        )
        .unwrap();
        let entropy_res = handle_tool_call(
            "inspect_byte_entropy",
            &json!({ "path": temp_bin.to_string_lossy() }),
        )
        .unwrap();
        assert!(entropy_res["overall_entropy"].as_f64().unwrap() > 0.0);

        let strings_res = handle_tool_call(
            "list_strings",
            &json!({ "path": temp_bin.to_string_lossy(), "min_length": 4 }),
        )
        .unwrap();
        assert!(
            strings_res["strings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s.as_str().unwrap().contains("HELLO_WORLD"))
        );

        // 5. inspect_artifact universal
        let artifact_res = handle_tool_call(
            "inspect_artifact",
            &json!({ "path": temp_bin.to_string_lossy() }),
        )
        .unwrap();
        assert_eq!(artifact_res["artifact_kind"], "file");

        let _ = std::fs::remove_file(temp_bin);

        // 6. compare_wasm_interfaces
        let wasm_sample = b"\0asm\x01\0\0\0";
        let wasm_file1 = std::env::temp_dir().join(format!("test_w1_{}.wasm", std::process::id()));
        let wasm_file2 = std::env::temp_dir().join(format!("test_w2_{}.wasm", std::process::id()));
        std::fs::write(&wasm_file1, wasm_sample).unwrap();
        std::fs::write(&wasm_file2, wasm_sample).unwrap();
        let wasm_diff = handle_tool_call(
            "compare_wasm_interfaces",
            &json!({
                "left_path": wasm_file1.to_string_lossy(),
                "right_path": wasm_file2.to_string_lossy()
            }),
        )
        .unwrap();
        assert!(wasm_diff["is_identical"].as_bool().unwrap());
        let _ = std::fs::remove_file(wasm_file1);
        let _ = std::fs::remove_file(wasm_file2);
    }
}
