use flate2::read::GzDecoder;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::OnceLock;

static CATALOG_GZ: &[u8] = include_bytes!("catalog.gz");
static ALL_TOOLS: OnceLock<Vec<Value>> = OnceLock::new();
static CORE_TOOLS: OnceLock<Vec<Value>> = OnceLock::new();

pub const CORE_TOOL_NAMES: &[&str] = &[
    "inspect_asar",
    "pack_asar",
    "extract_artifact",
    "analyze_javascript_application",
    "analyze_electron_source",
    "inspect_electron_fuses",
    "recover_javascript_sources",
    "extract_sourcemap",
    "run_audit_pipeline",
    "scan_secrets",
    "audit_tauri",
    "diff_applications",
    "compare_application_versions",
    "compare_source_to_bundle",
    "compare_javascript_export_shapes",
    "trace_application_feature",
    "trace_javascript_semantics",
    "inspect_binary_layout",
    "inspect_go_binary",
    "inspect_rust_binary",
    "inspect_wasm_artifact",
    "inspect_android_package",
    "inspect_sqlite_database",
    "inspect_packet_capture",
    "inspect_plist",
    "project_apple_application_graph",
    "project_harmony_application_graph",
    "inspect_managed_artifact",
    "inspect_managed_members",
    "list_browser_targets",
    "list_electron_targets",
    "list_adb_devices",
    "inspect_adb_device",
    "list_adb_packages",
    "list_live_processes",
    "inspect_live_process",
    "execute_gdb",
    "execute_frida",
    "inspect_with_objdump",
    "execute_rizin",
    "decode_signal_sigrok",
    "decompile_apktool_jadx",
    "rea_search_tools",
    "rea_execute_tool",
];

/// Meta-tools for dynamic on-demand tool discovery and execution
fn meta_tools() -> Vec<Value> {
    vec![
        json!({
            "name": "rea_search_tools",
            "description": "Search all 245 registered tools and inspect their implementation-route classification. Unavailable tools are included for discovery.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Keyword to search across tool names and descriptions"
                    }
                },
                "required": ["query"]
            }
        }),
        json!({
            "name": "rea_execute_tool",
            "description": "Attempt to execute a registered tool. Many of the 245 catalog entries require an external provider or are unavailable; use rea_search_tools to inspect routing first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": {
                        "type": "string",
                        "description": "Exact name of the tool to execute"
                    },
                    "arguments": {
                        "type": "object",
                        "description": "Arguments object passed to the tool"
                    }
                },
                "required": ["tool_name"]
            }
        }),
    ]
}

/// Sanitize tool schema: strip outputSchema, non-standard fields, and truncate overlong descriptions
fn sanitize_tool(mut tool: Value) -> Value {
    if let Value::Object(ref mut map) = tool {
        map.remove("outputSchema");
        map.remove("title");
        map.remove("annotations");
        map.remove("identity");

        if let Some(desc) = map.get_mut("description")
            && let Some(s) = desc.as_str()
            && s.len() > 250
        {
            let first_line = s.lines().next().unwrap_or(s);
            if first_line.len() > 250 {
                *desc = Value::String(format!("{}...", &first_line[..247]));
            } else {
                *desc = Value::String(first_line.to_string());
            }
        }
    }
    tool
}

/// 14 extra native tools provided by rea-fast that are not in the standard rea catalog
fn extra_native_tools() -> Vec<Value> {
    vec![
        json!({
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
        }),
        json!({
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
        }),
        json!({
            "name": "extract_sourcemap",
            "description": "Extract sourcesContent and source files from a SourceMap v3 JSON or inline data URI.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "map_path": {
                        "type": "string",
                        "description": "Local path to .map file or JS file containing inline map"
                    },
                    "output_directory": {
                        "type": "string",
                        "description": "Directory where extracted source files will be written"
                    }
                },
                "required": ["map_path", "output_directory"]
            }
        }),
        json!({
            "name": "run_audit_pipeline",
            "description": "Run end-to-end multi-stage security and architecture audit on an ASAR, directory, or binary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_path": {
                        "type": "string",
                        "description": "Local filesystem path to ASAR, folder, or binary"
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Optional workspace directory for output reports"
                    }
                },
                "required": ["target_path"]
            }
        }),
        json!({
            "name": "pack_asar",
            "description": "Pack a directory into a Chromium Pickle ASAR archive with 512 KiB block SHA-256 integrity hashing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "src_dir": {
                        "type": "string",
                        "description": "Source directory containing files to pack"
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Output path for the generated .asar file"
                    }
                },
                "required": ["src_dir", "output_path"]
            }
        }),
        json!({
            "name": "scan_secrets",
            "description": "Scan files or code strings for high-entropy API keys, tokens (AWS, GitHub, Slack, Stripe, JWT, Private Keys) and API route endpoints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Local file or directory path to scan"
                    },
                    "source": {
                        "type": "string",
                        "description": "Optional inline code string to scan directly"
                    }
                }
            }
        }),
        json!({
            "name": "audit_tauri",
            "description": "Fingerprint and audit Tauri desktop binaries (v1/v2), extract embedded tauri.conf.json, recover HTML/Brotli assets, and catalog IPC commands.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Local filesystem path to Tauri native executable"
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Optional directory to dump recovered web assets"
                    }
                },
                "required": ["path"]
            }
        }),
        json!({
            "name": "list_live_processes",
            "description": "List running processes on the host with command-line arguments and optional name/substring filtering.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "Case-insensitive substring filter for process name or cmdline"
                    }
                }
            }
        }),
        json!({
            "name": "inspect_live_process",
            "description": "Inspect detailed live host process state, VmRSS, VmSize, thread count, and mapped dynamic libraries (.so) from /proc.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID (PID) to inspect"
                    }
                },
                "required": ["pid"]
            }
        }),
        json!({
            "name": "execute_gdb",
            "description": "Execute GDB CLI command with child process timeout enforcement and background pipe draining.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command-line arguments passed to gdb"
                    }
                }
            }
        }),
        json!({
            "name": "execute_frida",
            "description": "Execute Frida CLI command with child process timeout enforcement and background pipe draining.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command-line arguments passed to frida / frida-ps"
                    }
                }
            }
        }),
        json!({
            "name": "execute_rizin",
            "description": "Execute Rizin CLI command with child process timeout enforcement and background pipe draining.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command-line arguments passed to rizin"
                    }
                }
            }
        }),
        json!({
            "name": "decode_signal_sigrok",
            "description": "Execute sigrok-cli to decode signal recordings with child process timeout enforcement and background pipe draining.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command-line arguments passed to sigrok-cli"
                    }
                }
            }
        }),
        json!({
            "name": "decompile_apktool_jadx",
            "description": "Execute jadx or apktool to decompile Android APK packages with child process timeout enforcement and background pipe draining.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command-line arguments passed to jadx or apktool"
                    }
                }
            }
        }),
    ]
}

/// Load and merge catalog tools with extra native tools and sanitize bloated schemas
fn load_tools() -> Vec<Value> {
    let decoder = GzDecoder::new(CATALOG_GZ);
    let catalog_tools = match serde_json::from_reader::<_, Value>(decoder) {
        Ok(mut doc) => {
            if let Some(tools) = doc.get_mut("tools").and_then(|t| t.as_array_mut()) {
                std::mem::take(tools)
            } else {
                Vec::new()
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to decompress mcp catalog: {e}");
            Vec::new()
        }
    };

    let mut sanitized_tools = Vec::new();
    for tool in catalog_tools {
        sanitized_tools.push(sanitize_tool(tool));
    }

    let mut existing_names = HashSet::new();
    for t in &sanitized_tools {
        if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
            existing_names.insert(name.to_string());
        }
    }

    // Append extra native tools that do not appear in catalog
    for extra in extra_native_tools() {
        if let Some(name) = extra.get("name").and_then(|n| n.as_str())
            && !existing_names.contains(name)
        {
            sanitized_tools.push(sanitize_tool(extra));
        }
    }

    // Append meta-tools for dynamic discovery and execution
    for meta in meta_tools() {
        if let Some(name) = meta.get("name").and_then(|n| n.as_str())
            && !existing_names.contains(name)
        {
            sanitized_tools.push(sanitize_tool(meta));
        }
    }

    sanitized_tools
}

/// Retrieve all 245 MCP tools lazily decompressed and sanitized from embedded catalog
pub fn get_all_tools() -> &'static [Value] {
    ALL_TOOLS.get_or_init(load_tools)
}

/// Retrieve the curated core native tools (~40 tools, ~25KB, lean context window)
pub fn get_core_tools() -> &'static [Value] {
    CORE_TOOLS.get_or_init(|| {
        let all = get_all_tools();
        all.iter()
            .filter(|t| {
                if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                    CORE_TOOL_NAMES.contains(&name)
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    })
}

/// Search all tools in the catalog by keyword
pub fn search_tools(query: &str) -> Vec<Value> {
    let q = query.to_lowercase();
    get_all_tools()
        .iter()
        .filter(|t| {
            let name = t
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_lowercase();
            let desc = t
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_lowercase();
            name.contains(&q) || desc.contains(&q)
        })
        .cloned()
        .collect()
}

/// Check if a tool is registered in the catalog
pub fn has_tool(name: &str) -> bool {
    get_all_tools()
        .iter()
        .any(|t| t.get("name").and_then(|n| n.as_str()) == Some(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_tools_count() {
        let tools = get_all_tools();
        assert_eq!(
            tools.len(),
            245,
            "Expected exactly 245 tools, got {}",
            tools.len()
        );
        let core = get_core_tools();
        assert!(
            core.len() >= 35,
            "Expected at least 35 core tools, got {}",
            core.len()
        );
    }

    #[test]
    fn test_catalog_contains_key_tools() {
        assert!(has_tool("inspect_electron_fuses"));
        assert!(has_tool("analyze_javascript_application"));
        assert!(has_tool("inspect_asar"));
        assert!(has_tool("open_binary"));
        assert!(has_tool("analyze_function"));
        assert!(has_tool("decompile_jeb_item"));
        assert!(has_tool("inspect_with_objdump"));
        assert!(has_tool("rea_search_tools"));
        assert!(has_tool("rea_execute_tool"));
    }

    #[test]
    fn test_search_tools() {
        let matches = search_tools("gdb");
        assert!(!matches.is_empty(), "Should find gdb tools");
        assert!(matches.iter().any(|t| t["name"] == "execute_gdb"));
    }
}
