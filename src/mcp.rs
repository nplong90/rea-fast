use crate::{
    analyze::{self, FileAnalysis},
    asar::{self, AsarArchive, IntegrityPolicy},
    bundle::{ExtractionMode, RewriteLevel, SourceRecoverer},
    diff::ApplicationDiffer,
    electron, fuses, graph,
    semantics::{self, SemanticQuery},
    trace::{ApplicationFeatureTracer, FeatureSeed, TraceDirection},
};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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

pub fn analyze_application(
    input: &Path,
    max_file_bytes: u64,
) -> Result<Value, Box<dyn Error>> {
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
        if let Some(p) = obj.get("input_path").or_else(|| obj.get("path")).and_then(|v| v.as_str()) {
            let path = Path::new(p);
            if path.exists() {
                return analyze_application(path, 16_777_216).map_err(|e| e.to_string());
            }
        }
        if let Some(subj) = obj.get("subject").and_then(|s| s.get("local_path")).and_then(|v| v.as_str()) {
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
        if let Some(p) = obj.get("input_path").or_else(|| obj.get("path")).and_then(|v| v.as_str()) {
            let path = Path::new(p);
            if path.exists() {
                return Some(path.to_path_buf());
            }
        }
        if let Some(subj) = obj.get("subject").and_then(|s| s.get("local_path")).and_then(|v| v.as_str()) {
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

pub fn build_application_semantic_graph(input: &Path) -> Result<semantics::SemanticGraph, Box<dyn Error>> {
    let input = input.canonicalize()?;
    let mut combined = semantics::SemanticGraph::default();
    if is_asar(&input) {
        let archive = AsarArchive::open(&input)?;
        for entry in &archive.entries {
            if supported(Path::new(&entry.path)) && !entry.unpacked {
                if let Ok(bytes) = archive.read_file(entry) {
                    if let Ok(source) = std::str::from_utf8(&bytes) {
                        let g = semantics::build_semantic_graph(source, &entry.path);
                        combined.nodes.extend(g.nodes);
                        combined.edges.extend(g.edges);
                    }
                }
            }
        }
    } else if input.is_file() {
        let source = std::fs::read_to_string(&input)?;
        let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("file.js");
        combined = semantics::build_semantic_graph(&source, name);
    } else {
        let root = &input;
        let files = collect_files(&input)?;
        for path in files {
            if let Ok(source) = std::fs::read_to_string(&path) {
                let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().to_string();
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

fn tool_list() -> Value {
    json!({
        "tools": [
            {
                "name": "inspect_electron_fuses",
                "description": "Inspect packaged Electron fuse bytes in a macOS .app, Electron Framework, Windows PE, or Linux ELF executable.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute filesystem path to executable or app bundle"
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "analyze_javascript_application",
                "description": "Reconstruct local ASAR or extracted JavaScript/TypeScript application as an inline application graph.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "input_path": {
                            "type": "string",
                            "description": "Local filesystem path to ASAR or directory"
                        },
                        "max_file_bytes": {
                            "type": "integer",
                            "description": "Optional max file bytes limit"
                        }
                    },
                    "required": ["input_path"]
                }
            },
            {
                "name": "inspect_asar",
                "description": "Inspect contents of a Chromium Pickle ASAR archive without unpacking.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Local path to .asar file"
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "analyze_electron_source",
                "description": "Statically analyze Electron source code for IPC channels, sender validation, webPreferences, and utilityProcess.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Local file path or virtual path"
                        },
                        "source": {
                            "type": "string",
                            "description": "Optional source code. If omitted, reads from path."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "extract_artifact",
                "description": "Extract all regular files from an ASAR archive or application package into a directory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Local filesystem path to ASAR or package"
                        },
                        "output_directory": {
                            "type": "string",
                            "description": "Optional destination directory. If omitted, uses fresh temp dir."
                        },
                        "integrity_policy": {
                            "type": "string",
                            "enum": ["fail", "record-and-continue"],
                            "description": "Integrity policy: 'fail' or 'record-and-continue'"
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "recover_javascript_sources",
                "description": "Recover readable modules from JavaScript bundles into an output directory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to UTF-8 bundle file"
                        },
                        "output_directory": {
                            "type": "string",
                            "description": "Absolute output directory"
                        },
                        "extraction_mode": {
                            "type": "string",
                            "enum": ["structural", "heuristic", "inspection"]
                        },
                        "rewrite_level": {
                            "type": "string",
                            "enum": ["minimal", "standard", "aggressive"]
                        }
                    },
                    "required": ["path", "output_directory"]
                }
            },
            {
                "name": "compare_application_versions",
                "description": "Compare two JavaScript Application Graph versions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "left": {
                            "description": "Left graph (path, JSON string, or graph object)"
                        },
                        "right": {
                            "description": "Right graph (path, JSON string, or graph object)"
                        }
                    },
                    "required": ["left", "right"]
                }
            },
            {
                "name": "compare_javascript_export_shapes",
                "description": "Compare static return shapes for one exact module/export selector on two Application Graphs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "left": {
                            "description": "Left graph"
                        },
                        "left_module_path": {
                            "type": "string"
                        },
                        "left_export_name": {
                            "type": "string"
                        },
                        "right": {
                            "description": "Right graph"
                        },
                        "right_module_path": {
                            "type": "string"
                        },
                        "right_export_name": {
                            "type": "string"
                        }
                    },
                    "required": [
                        "left",
                        "left_module_path",
                        "left_export_name",
                        "right",
                        "right_module_path",
                        "right_export_name"
                    ]
                }
            },
            {
                "name": "trace_application_feature",
                "description": "Trace a literal seed through reachable parts of a JavaScript Application Graph.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "application": {
                            "description": "Application path or graph object"
                        },
                        "seed": {
                            "type": "object",
                            "properties": {
                                "kind": { "type": "string" },
                                "value": { "type": "string" },
                                "match": { "type": "string" },
                                "case_sensitive": { "type": "boolean" }
                            },
                            "required": ["kind", "value"]
                        },
                        "direction": {
                            "type": "string",
                            "enum": ["outgoing", "incoming", "both"]
                        }
                    },
                    "required": ["application", "seed"]
                }
            },
            {
                "name": "trace_javascript_semantics",
                "description": "Trace static JavaScript data-flow, direct call/return, and closure relations.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "application": {
                            "description": "Application path, inline code string, or semantic graph object"
                        },
                        "query": {
                            "type": "object",
                            "properties": {
                                "seed": { "type": "object" },
                                "direction": { "type": "string" },
                                "allowed_relations": { "type": "array" },
                                "expected": { "type": "object" },
                                "include_ambiguous_dynamic_edges": { "type": "boolean" }
                            },
                            "required": ["seed", "direction"]
                        }
                    },
                    "required": ["application", "query"]
                }
            }
        ]
    })
}

pub fn handle_tool_call(name: &str, args: &Value) -> Result<Value, String> {
    match name {
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
            let summary = json!({
                "path": path_str,
                "total_entries": archive.entries.len(),
                "entries": archive.entries.iter().map(|e| json!({
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
            let out_dir = args.get("output_directory").and_then(|v| v.as_str()).map(Path::new);
            let policy = match args.get("integrity_policy").and_then(|v| v.as_str()) {
                Some("record-and-continue") => IntegrityPolicy::RecordAndContinue,
                _ => IntegrityPolicy::Fail,
            };
            let res = asar::extract_artifact(Path::new(path_str), out_dir, policy).map_err(|e| e.to_string())?;
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
        "compare_application_versions" => {
            let left_val = args.get("left").ok_or_else(|| "Missing 'left' argument".to_string())?;
            let right_val = args.get("right").ok_or_else(|| "Missing 'right' argument".to_string())?;
            let left_g = resolve_graph_value(left_val)?;
            let right_g = resolve_graph_value(right_val)?;
            let diff = ApplicationDiffer::compare_applications(&left_g, &right_g)?;
            serde_json::to_value(diff).map_err(|e| e.to_string())
        }
        "compare_javascript_export_shapes" => {
            let left_val = args.get("left").ok_or_else(|| "Missing 'left' argument".to_string())?;
            let left_mod = args
                .get("left_module_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'left_module_path' argument".to_string())?;
            let left_exp = args
                .get("left_export_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'left_export_name' argument".to_string())?;
            let right_val = args.get("right").ok_or_else(|| "Missing 'right' argument".to_string())?;
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
        "trace_application_feature" => {
            let app_val = args.get("application").ok_or_else(|| "Missing 'application' argument".to_string())?;
            let seed: FeatureSeed = serde_json::from_value(args.get("seed").cloned().unwrap_or(Value::Null))
                .map_err(|e| format!("Invalid 'seed' argument: {e}"))?;
            let direction = match args.get("direction").and_then(|v| v.as_str()) {
                Some("incoming") => TraceDirection::Incoming,
                Some("outgoing") => TraceDirection::Outgoing,
                _ => TraceDirection::Both,
            };
            let path = resolve_input_path(app_val).ok_or_else(|| "Unable to resolve application path".to_string())?;
            let files = analyze_application_files(&path, 16_777_216).map_err(|e| e.to_string())?;
            let deps = graph::dependencies(&files);
            let tracer = ApplicationFeatureTracer::new(&files, &deps, None);
            let res = tracer.trace(&seed, direction);
            serde_json::to_value(res).map_err(|e| e.to_string())
        }
        "trace_javascript_semantics" => {
            let app_val = args.get("application").ok_or_else(|| "Missing 'application' argument".to_string())?;
            let query: SemanticQuery = serde_json::from_value(args.get("query").cloned().unwrap_or(Value::Null))
                .map_err(|e| format!("Invalid 'query' argument: {e}"))?;
            let graph = if let Ok(g) = serde_json::from_value::<semantics::SemanticGraph>(app_val.clone()) {
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
        _ => Err(format!("Unknown tool: {name}")),
    }
}

pub fn run_mcp_server() -> Result<(), Box<dyn Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(e.into()),
        };
        let trimmed = line.trim();
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

        let id = req.id.unwrap_or(Value::Null);

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
    fn tool_list_contains_expected_tools() {
        let tools = tool_list();
        let list = tools["tools"].as_array().unwrap();
        let names: Vec<_> = list.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(list.len(), 10);
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
        let aligned_json = (text.len() + 3) / 4 * 4;
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
        assert_eq!(std::fs::read(out_dir.join("main.js")).unwrap(), b"console.log()");

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
        let bundle_file = std::env::temp_dir().join(format!("test_bundle_{}.js", std::process::id()));
        let out_dir = std::env::temp_dir().join(format!("test_recover_{}", std::process::id()));
        std::fs::write(&bundle_file, bundle_code).unwrap();

        let args = json!({
            "path": bundle_file.to_string_lossy(),
            "output_directory": out_dir.to_string_lossy(),
            "extraction_mode": "structural",
            "rewrite_level": "standard"
        });
        let res = handle_tool_call("recover_javascript_sources", &args).unwrap();
        assert!(res["recovered_modules"].as_array().unwrap().len() >= 1);
        assert!(out_dir.join("src/app.js").exists());

        let _ = std::fs::remove_file(bundle_file);
        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn handles_analyze_javascript_application_and_trace_feature_tool_calls() {
        let app_dir = std::env::temp_dir().join(format!("test_app_{}", std::process::id()));
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::write(app_dir.join("index.js"), "import { auth } from './auth.js'; auth();").unwrap();
        std::fs::write(app_dir.join("auth.js"), "export function auth() { return 'secret_token'; }").unwrap();

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
        assert!(visited.iter().any(|v| v.as_str().unwrap().contains("auth.js")));

        let _ = std::fs::remove_dir_all(app_dir);
    }
}
