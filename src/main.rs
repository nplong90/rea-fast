#![recursion_limit = "256"]

mod analyze;
mod asar;
pub mod bundle;
pub mod capabilities;
pub mod catalog;
pub mod cdp;
pub mod diff;
pub mod dynamic_bridge;
mod electron;
pub mod evidence;
mod fuses;
mod graph;
pub mod managed;
mod mcp;
pub mod mobile;
pub mod native_binary;
pub mod pipeline;
pub mod plist;
pub mod secrets;
pub mod security_io;
pub mod semantics;
pub mod session_manager;
pub mod sourcemap;
pub mod storage_pcap;
pub mod tauri;
pub mod tcp_driver;
pub mod trace;

use clap::{Parser, ValueEnum};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::json;
use std::{
    error::Error,
    io::{self, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Parser)]
#[command(
    version,
    about = "Parallel, non-executing JavaScript/TypeScript structural analysis & REA toolkit"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to analyze (when no subcommand is specified)
    path: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "summary")]
    format: Format,
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Files larger than this limit remain explicitly unavailable.
    #[arg(long, default_value_t = 16_777_216, value_parser = clap::value_parser!(u64).range(1..))]
    max_file_bytes: u64,
    /// Run as MCP JSON-RPC stdio server
    #[arg(long)]
    mcp: bool,
}

#[derive(clap::Subcommand)]
#[command(rename_all = "kebab-case")]
enum Commands {
    /// Run as Model Context Protocol (MCP) JSON-RPC stdio server
    Mcp {
        /// Tool catalog profile: 'core' (default, ~40 tools, ~25KB lean context) or 'full' (all 245 tools)
        #[arg(long, default_value = "core")]
        profile: String,
    },
    /// Run parallel structural AST analysis on JS/TS folder or ASAR archive
    Analyze {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "summary")]
        format: Format,
        #[arg(long, default_value_t = 0)]
        threads: usize,
        #[arg(long, default_value_t = 16_777_216)]
        max_file_bytes: u64,
    },
    /// Inspect Electron fuse bytes in binary executable
    Fuses { path: PathBuf },
    /// Inspect Chromium Pickle ASAR directory header without unpacking
    InspectAsar { path: PathBuf },
    /// Extract files from ASAR archive with integrity verification
    Extract {
        path: PathBuf,
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "fail")]
        integrity_policy: CliIntegrityPolicy,
    },
    /// Recover readable JS modules from bundle files
    Recover {
        path: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "structural")]
        extraction_mode: String,
        #[arg(long, default_value = "standard")]
        rewrite_level: String,
    },
    /// Compare two application graphs or paths
    Diff { left: String, right: String },
    /// Compare export shapes between modules across application graphs
    ExportShapes {
        #[arg(long)]
        left: String,
        #[arg(long)]
        left_module: String,
        #[arg(long)]
        left_export: String,
        #[arg(long)]
        right: String,
        #[arg(long)]
        right_module: String,
        #[arg(long)]
        right_export: String,
    },
    /// Trace feature seed reachability across application graph
    TraceFeature {
        app: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        value: String,
        #[arg(long, default_value = "contains")]
        match_mode: String,
        #[arg(long, default_value = "both")]
        direction: String,
        #[arg(long)]
        case_sensitive: bool,
    },
    /// Trace JavaScript semantic data-flow and call edges
    TraceSemantics {
        app: String,
        #[arg(long)]
        node_id: String,
        #[arg(long, default_value = "forward-influence")]
        direction: String,
    },
    /// Analyze Electron source code for IPC and security anti-patterns
    AnalyzeElectron {
        path: PathBuf,
        #[arg(long)]
        source: Option<String>,
    },
    /// Extract sourcesContent from a SourceMap v3 file or inline data URI
    Sourcemap {
        path: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
    },
    /// Run automated end-to-end security audit pipeline on target
    Audit {
        path: PathBuf,
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },
    /// Pack a directory of files into a Chromium Pickle ASAR archive with SHA-256 block hashing
    PackAsar { src_dir: PathBuf, output: PathBuf },
    /// Scan files, directory, or inline string for high-entropy secrets and exposed API endpoints
    Secrets {
        path: Option<PathBuf>,
        #[arg(long)]
        source: Option<String>,
    },
    /// Audit Tauri desktop binary for framework signals, embedded config, assets, and IPC calls
    AuditTauri {
        path: PathBuf,
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },
    /// Inspect binary layout (sections, entry point, symbols, imports) for ELF, PE, Mach-O
    InspectBinary { path: PathBuf },
    /// Inspect embedded Go buildinfo, version, module path, dependencies
    InspectGo { path: PathBuf },
    /// Inspect Rust compiler commit and cargo-auditable dependency graph
    InspectRust { path: PathBuf },
    /// Inspect WebAssembly binary sections, imports, and exports
    InspectWasm { path: PathBuf },
    /// Inspect Android APK manifest, permissions, activities, dex, and native libraries
    InspectApk { path: PathBuf },
    /// Inspect SQLite database header, page size, cookies, and table schemas
    InspectSqlite { path: PathBuf },
    /// Inspect PCAP / PCAPNG packet captures (protocols, IP/port sets, packet counts)
    InspectPcap { path: PathBuf },
    /// List targets from loopback Chrome/Electron CDP endpoint
    ListCdpTargets {
        #[arg(long, default_value = "http://127.0.0.1:9222")]
        endpoint: String,
    },
    /// List Electron page/app targets from loopback CDP endpoint
    ListElectronTargets {
        #[arg(long, default_value = "http://127.0.0.1:9222")]
        endpoint: String,
    },
    /// Capture screenshot of web or Electron page via CDP
    Screenshot {
        #[arg(long, default_value = "http://127.0.0.1:9222")]
        endpoint: String,
        #[arg(short, long)]
        target_id: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Evaluate JavaScript expression in page runtime via CDP
    Eval {
        #[arg(long, default_value = "http://127.0.0.1:9222")]
        endpoint: String,
        #[arg(short, long)]
        target_id: Option<String>,
        expression: String,
    },
    /// Inspect live web or Electron page DOM and scripts via CDP
    InspectWebPage {
        #[arg(long, default_value = "http://127.0.0.1:9222")]
        endpoint: String,
        #[arg(short, long)]
        target_id: Option<String>,
    },
    /// List connected Android devices and emulators via adb
    ListAdbDevices,
    /// Inspect Android device properties, model, ABI, and emulator status
    InspectAdbDevice {
        #[arg(short, long)]
        serial: Option<String>,
    },
    /// List installed Android packages on device
    ListAdbPackages {
        #[arg(short, long)]
        serial: Option<String>,
        #[arg(long)]
        third_party: bool,
    },
    /// List live host processes with PID, comm name, and cmdline
    ListProcesses {
        #[arg(short, long)]
        filter: Option<String>,
    },
    /// Inspect detailed live host process state, memory, threads, and mapped libraries
    InspectProcess { pid: u32 },
    /// Execute GDB bridge if installed or print diagnostic installation instructions
    Gdb {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Execute Frida bridge if installed or print diagnostic installation instructions
    Frida {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Inspect binary with objdump if installed or print diagnostic installation instructions
    Objdump {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Execute Rizin bridge if installed or print diagnostic installation instructions
    Rizin {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Decode signal using sigrok-cli if installed or print diagnostic installation instructions
    Sigrok {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Decompile Android APK with jadx/apktool if installed or print diagnostic installation instructions
    DecompileAndroid {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Inspect binary or XML Apple property list (.plist) file
    InspectPlist { path: PathBuf },
    /// Project Apple Application Graph (.app, Frameworks, PlugIns, XPC)
    ProjectApple { path: PathBuf },
    /// Inspect .NET PE CLI metadata or IL2CPP global-metadata.dat
    InspectManaged { path: PathBuf },
    /// Query or export Evidence DAG and residual unknowns
    EvidenceBundle {
        #[arg(short, long)]
        export: Option<PathBuf>,
    },
    /// Inspect universal artifact (ASAR, APK, SQLite, PCAP, Plist, ELF, Mach-O, PE, WASM)
    InspectArtifact { path: PathBuf },
    /// Inspect machine learning model artifact (GGUF, SafeTensors, TFLite)
    InspectModel { path: PathBuf },
    /// Inspect Shannon byte entropy of file or binary sections
    InspectEntropy { path: PathBuf },
    /// Extract printable ASCII strings from file or binary
    Strings {
        path: PathBuf,
        #[arg(short, long, default_value_t = 4)]
        min_len: usize,
    },
    /// Identify Flutter framework build, libraries, and assets
    IdentifyFlutter { path: PathBuf },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliIntegrityPolicy {
    Fail,
    RecordAndContinue,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Summary,
    Json,
    JsonSummary,
}

#[derive(Default, Serialize)]
struct Summary {
    total_files: usize,
    total_bytes: usize,
    total_lines: usize,
    total_imports: usize,
    total_exports: usize,
    total_functions: usize,
    total_classes: usize,
    total_symbols: usize,
    parse_errors: usize,
    unavailable_files: usize,
    internal_dependencies: usize,
    unresolved_dependencies: usize,
    elapsed_ms: f64,
    files_per_second: f64,
    mb_per_second: f64,
    threads_used: usize,
}

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
    let mut budget = security_io::ProjectBudget::default();
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
            budget.claim_path(entry.path())?;
            files.push(entry.into_path());
        }
    }
    files.sort();
    Ok(files)
}

fn print_tool_result(res: Result<serde_json::Value, String>) -> Result<(), Box<dyn Error>> {
    match res {
        Ok(val) => {
            let mut out = io::BufWriter::new(io::stdout().lock());
            serde_json::to_writer_pretty(&mut out, &val)?;
            writeln!(out)?;
            out.flush()?;
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

fn execute_analysis(
    path: &Path,
    format: Format,
    threads: usize,
    max_file_bytes: u64,
) -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let input = path.canonicalize()?;
    if input.is_file() && !supported(&input) && !is_asar(&input) {
        return Err("Expected a JS/TS file, directory, or .asar archive".into());
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;
    let results: Vec<_> = if is_asar(&input) {
        let archive = asar::AsarArchive::open(&input)?;
        let entries: Vec<_> = archive
            .entries
            .iter()
            .filter(|e| supported(Path::new(&e.path)))
            .cloned()
            .collect();
        if entries.is_empty() {
            return Err("No JS/TS files found in ASAR".into());
        }
        let mut budget = security_io::ProjectBudget::default();
        for entry in &entries {
            budget.claim_size(entry.size)?;
        }
        pool.install(|| {
            entries
                .par_iter()
                .map(|entry| {
                    if entry.size > max_file_bytes {
                        return analyze::FileAnalysis {
                            path: entry.path.clone(),
                            error: Some(format!("File exceeds --max-file-bytes={max_file_bytes}")),
                            ..Default::default()
                        };
                    }
                    match archive.read_file(entry) {
                        Ok(bytes) => match std::str::from_utf8(&bytes) {
                            Ok(source) => analyze::analyze_source(source, &entry.path),
                            Err(_) => analyze::FileAnalysis {
                                path: entry.path.clone(),
                                error: Some("File is not valid UTF-8".into()),
                                ..Default::default()
                            },
                        },
                        Err(e) => analyze::FileAnalysis {
                            path: entry.path.clone(),
                            error: Some(e.to_string()),
                            ..Default::default()
                        },
                    }
                })
                .collect()
        })
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
        pool.install(|| {
            files
                .par_iter()
                .map(|path| analyze::analyze_file(path, root, max_file_bytes))
                .collect()
        })
    };
    let dependencies = graph::dependencies(&results);
    let mut summary = Summary {
        total_files: results.len(),
        threads_used: pool.current_num_threads(),
        ..Summary::default()
    };
    for file in &results {
        summary.total_bytes += file.bytes;
        summary.total_lines += file.lines;
        summary.total_imports += file.imports.len();
        summary.total_exports += file.exports.len();
        summary.total_functions += file.functions.len();
        summary.total_classes += file.classes.len();
        summary.total_symbols += file.symbols;
        summary.parse_errors += file.parse_errors;
        summary.unavailable_files += usize::from(file.error.is_some());
    }
    summary.internal_dependencies = dependencies
        .iter()
        .flatten()
        .filter(|d| d.target.is_some())
        .count();
    summary.unresolved_dependencies = dependencies
        .iter()
        .flatten()
        .filter(|d| d.target.is_none())
        .count();
    let elapsed = start.elapsed().as_secs_f64();
    summary.elapsed_ms = elapsed * 1000.0;
    summary.files_per_second = summary.total_files as f64 / elapsed;
    summary.mb_per_second = summary.total_bytes as f64 / 1_048_576.0 / elapsed;
    let mut out = io::BufWriter::new(io::stdout().lock());
    match format {
        Format::Json => graph::write_graph(&mut out, &results, &dependencies, max_file_bytes)?,
        Format::JsonSummary => serde_json::to_writer(&mut out, &summary)?,
        Format::Summary => write!(
            out,
            "Files       {:>12}\nLOC         {:>12}\nBytes       {:>12}\nImports     {:>12}\nExports     {:>12}\nFunctions   {:>12}\nClasses     {:>12}\nSymbols     {:>12}\nParse errors{:>12}\nUnavailable {:>12}\nInternal dependencies {:>6}\nUnresolved/external   {:>6}\nThreads     {:>12}\nAnalysis ms {:>12.2}\nFiles/s     {:>12.0}\nMiB/s       {:>12.2}\n",
            summary.total_files,
            summary.total_lines,
            summary.total_bytes,
            summary.total_imports,
            summary.total_exports,
            summary.total_functions,
            summary.total_classes,
            summary.total_symbols,
            summary.parse_errors,
            summary.unavailable_files,
            summary.internal_dependencies,
            summary.unresolved_dependencies,
            summary.threads_used,
            summary.elapsed_ms,
            summary.files_per_second,
            summary.mb_per_second
        )?,
    }
    writeln!(out)?;
    out.flush()?;
    if summary.unavailable_files > 0 {
        return Err(format!(
            "{} files unavailable; output retains partial results",
            summary.unavailable_files
        )
        .into());
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    if cli.mcp {
        return mcp::run_mcp_server();
    }
    if let Some(command) = cli.command {
        match command {
            Commands::Mcp { profile } => {
                if profile == "full" {
                    mcp::set_profile_full(true);
                }
                mcp::run_mcp_server()
            }
            Commands::Analyze {
                path,
                format,
                threads,
                max_file_bytes,
            } => execute_analysis(&path, format, threads, max_file_bytes),
            Commands::Fuses { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_electron_fuses", &args))
            }
            Commands::InspectAsar { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_asar", &args))
            }
            Commands::Extract {
                path,
                output_dir,
                integrity_policy,
            } => {
                let mut args = json!({
                    "path": path.to_string_lossy(),
                    "integrity_policy": match integrity_policy {
                        CliIntegrityPolicy::Fail => "fail",
                        CliIntegrityPolicy::RecordAndContinue => "record-and-continue",
                    }
                });
                if let Some(out) = output_dir {
                    args["output_directory"] = json!(out.to_string_lossy());
                }
                print_tool_result(mcp::handle_tool_call("extract_artifact", &args))
            }
            Commands::Recover {
                path,
                output_dir,
                extraction_mode,
                rewrite_level,
            } => {
                let args = json!({
                    "path": path.to_string_lossy(),
                    "output_directory": output_dir.to_string_lossy(),
                    "extraction_mode": extraction_mode,
                    "rewrite_level": rewrite_level,
                });
                print_tool_result(mcp::handle_tool_call("recover_javascript_sources", &args))
            }
            Commands::Diff { left, right } => {
                let args = json!({ "left": left, "right": right });
                print_tool_result(mcp::handle_tool_call("compare_application_versions", &args))
            }
            Commands::ExportShapes {
                left,
                left_module,
                left_export,
                right,
                right_module,
                right_export,
            } => {
                let args = json!({
                    "left": left,
                    "left_module_path": left_module,
                    "left_export_name": left_export,
                    "right": right,
                    "right_module_path": right_module,
                    "right_export_name": right_export,
                });
                print_tool_result(mcp::handle_tool_call(
                    "compare_javascript_export_shapes",
                    &args,
                ))
            }
            Commands::TraceFeature {
                app,
                kind,
                value,
                match_mode,
                direction,
                case_sensitive,
            } => {
                let args = json!({
                    "application": app,
                    "seed": {
                        "kind": kind,
                        "value": value,
                        "match": match_mode,
                        "case_sensitive": case_sensitive,
                    },
                    "direction": direction,
                });
                print_tool_result(mcp::handle_tool_call("trace_application_feature", &args))
            }
            Commands::TraceSemantics {
                app,
                node_id,
                direction,
            } => {
                let args = json!({
                    "application": app,
                    "query": {
                        "seed": {
                            "kind": "semantic-node",
                            "node_id": node_id,
                        },
                        "direction": direction,
                    }
                });
                print_tool_result(mcp::handle_tool_call("trace_javascript_semantics", &args))
            }
            Commands::AnalyzeElectron { path, source } => {
                let mut args = json!({ "path": path.to_string_lossy() });
                if let Some(src) = source {
                    args["source"] = json!(src);
                }
                print_tool_result(mcp::handle_tool_call("analyze_electron_source", &args))
            }
            Commands::Sourcemap { path, output_dir } => {
                let args = json!({
                    "path": path.to_string_lossy(),
                    "output_directory": output_dir.to_string_lossy(),
                });
                print_tool_result(mcp::handle_tool_call("extract_sourcemap", &args))
            }
            Commands::Audit { path, output_dir } => {
                let mut args = json!({
                    "target_path": path.to_string_lossy(),
                });
                if let Some(out) = output_dir {
                    args["output_directory"] = json!(out.to_string_lossy());
                }
                print_tool_result(mcp::handle_tool_call("run_audit_pipeline", &args))
            }
            Commands::PackAsar { src_dir, output } => {
                let args = json!({
                    "source_directory": src_dir.to_string_lossy(),
                    "output_path": output.to_string_lossy(),
                });
                print_tool_result(mcp::handle_tool_call("pack_asar", &args))
            }
            Commands::Secrets { path, source } => {
                let mut args = json!({});
                if let Some(p) = path {
                    args["path"] = json!(p.to_string_lossy());
                }
                if let Some(s) = source {
                    args["source"] = json!(s);
                }
                print_tool_result(mcp::handle_tool_call("scan_secrets", &args))
            }
            Commands::AuditTauri { path, output_dir } => {
                let mut args = json!({
                    "path": path.to_string_lossy(),
                });
                if let Some(out) = output_dir {
                    args["output_directory"] = json!(out.to_string_lossy());
                }
                print_tool_result(mcp::handle_tool_call("audit_tauri", &args))
            }
            Commands::InspectBinary { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_binary_layout", &args))
            }
            Commands::InspectGo { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_go_binary", &args))
            }
            Commands::InspectRust { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_rust_binary", &args))
            }
            Commands::InspectWasm { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_wasm_artifact", &args))
            }
            Commands::InspectApk { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_android_package", &args))
            }
            Commands::InspectSqlite { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_sqlite_database", &args))
            }
            Commands::InspectPcap { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_packet_capture", &args))
            }
            Commands::ListCdpTargets { endpoint } => {
                let args = json!({ "cdp_endpoint": endpoint });
                print_tool_result(mcp::handle_tool_call("list_browser_targets", &args))
            }
            Commands::ListElectronTargets { endpoint } => {
                let args = json!({ "cdp_endpoint": endpoint });
                print_tool_result(mcp::handle_tool_call("list_electron_targets", &args))
            }
            Commands::Screenshot {
                endpoint,
                target_id,
                output,
            } => {
                let mut args = json!({ "cdp_endpoint": endpoint });
                if let Some(t) = target_id {
                    args["target_id"] = json!(t);
                }
                if let Some(o) = output {
                    args["output_file"] = json!(o.to_string_lossy());
                }
                print_tool_result(mcp::handle_tool_call("capture_web_screenshot", &args))
            }
            Commands::Eval {
                endpoint,
                target_id,
                expression,
            } => {
                let mut args = json!({ "cdp_endpoint": endpoint, "expression": expression });
                if let Some(t) = target_id {
                    args["target_id"] = json!(t);
                }
                print_tool_result(mcp::handle_tool_call("evaluate_web_script", &args))
            }
            Commands::InspectWebPage {
                endpoint,
                target_id,
            } => {
                let mut args = json!({ "cdp_endpoint": endpoint });
                if let Some(t) = target_id {
                    args["target_id"] = json!(t);
                }
                print_tool_result(mcp::handle_tool_call("inspect_web_page", &args))
            }
            Commands::ListAdbDevices => {
                let args = json!({});
                print_tool_result(mcp::handle_tool_call("list_adb_devices", &args))
            }
            Commands::InspectAdbDevice { serial } => {
                let mut args = json!({});
                if let Some(s) = serial {
                    args["serial"] = json!(s);
                }
                print_tool_result(mcp::handle_tool_call("inspect_adb_device", &args))
            }
            Commands::ListAdbPackages {
                serial,
                third_party,
            } => {
                let mut args = json!({ "third_party_only": third_party });
                if let Some(s) = serial {
                    args["serial"] = json!(s);
                }
                print_tool_result(mcp::handle_tool_call("list_adb_packages", &args))
            }
            Commands::ListProcesses { filter } => {
                let mut args = json!({});
                if let Some(f) = filter {
                    args["filter"] = json!(f);
                }
                print_tool_result(mcp::handle_tool_call("list_live_processes", &args))
            }
            Commands::InspectProcess { pid } => {
                let args = json!({ "pid": pid });
                print_tool_result(mcp::handle_tool_call("inspect_live_process", &args))
            }
            Commands::Gdb { args } => {
                let mcp_args = json!({ "args": args });
                print_tool_result(mcp::handle_tool_call("execute_gdb", &mcp_args))
            }
            Commands::Frida { args } => {
                let mcp_args = json!({ "args": args });
                print_tool_result(mcp::handle_tool_call("execute_frida", &mcp_args))
            }
            Commands::Objdump { args } => {
                let mcp_args = json!({ "args": args });
                print_tool_result(mcp::handle_tool_call("inspect_with_objdump", &mcp_args))
            }
            Commands::Rizin { args } => {
                let mcp_args = json!({ "args": args });
                print_tool_result(mcp::handle_tool_call("execute_rizin", &mcp_args))
            }
            Commands::Sigrok { args } => {
                let mcp_args = json!({ "args": args });
                print_tool_result(mcp::handle_tool_call("decode_signal_sigrok", &mcp_args))
            }
            Commands::DecompileAndroid { args } => {
                let mcp_args = json!({ "args": args });
                print_tool_result(mcp::handle_tool_call("decompile_apktool_jadx", &mcp_args))
            }
            Commands::InspectPlist { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_plist", &args))
            }
            Commands::ProjectApple { path } => {
                let args = json!({
                    "inventory_evidence": [{ "path": path.to_string_lossy() }]
                });
                print_tool_result(mcp::handle_tool_call(
                    "project_apple_application_graph",
                    &args,
                ))
            }
            Commands::InspectManaged { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_managed_artifact", &args))
            }
            Commands::EvidenceBundle { export } => {
                if let Some(exp) = export {
                    let args = json!({ "path": exp.to_string_lossy(), "overwrite": true });
                    print_tool_result(mcp::handle_tool_call("export_evidence_bundle", &args))
                } else {
                    let args = json!({ "detail": "summary" });
                    print_tool_result(mcp::handle_tool_call("get_evidence_bundle", &args))
                }
            }
            Commands::InspectArtifact { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_artifact", &args))
            }
            Commands::InspectModel { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_model_artifact", &args))
            }
            Commands::InspectEntropy { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("inspect_byte_entropy", &args))
            }
            Commands::Strings { path, min_len } => {
                let args = json!({ "path": path.to_string_lossy(), "min_length": min_len });
                print_tool_result(mcp::handle_tool_call("list_strings", &args))
            }
            Commands::IdentifyFlutter { path } => {
                let args = json!({ "path": path.to_string_lossy() });
                print_tool_result(mcp::handle_tool_call("identify_flutter_build", &args))
            }
        }
    } else if let Some(path) = cli.path {
        execute_analysis(&path, cli.format, cli.threads, cli.max_file_bytes)
    } else {
        Err("Path or subcommand required unless running with --mcp".into())
    }
}

fn main() {
    if let Err(error) = run() {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
        {
            return;
        }
        eprintln!("rea-fast: {error}");
        std::process::exit(1);
    }
}
