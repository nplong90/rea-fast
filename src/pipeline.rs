use crate::{
    analyze::{self, FileAnalysis},
    asar::{self, IntegrityPolicy},
    bundle::{ExtractionMode, RewriteLevel, SourceRecoverer},
    electron::{self, ElectronStaticFindings},
    fuses::{self, FuseReport, FuseState},
    graph,
    mobile::{AndroidPackageInfo, MobileInspector},
    native_binary::{BinaryLayout, GoBuildInfo, NativeInspector, RustBinaryInfo, WasmInterface},
    secrets::SecretScanner,
    sourcemap::SourceMapExtractor,
    storage_pcap::{PcapCaptureInfo, SqliteDbInfo, StoragePcapInspector},
    tauri::TauriScanner,
};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    AsarArchive,
    ElectronBinary,
    TauriBinary,
    SourceMap,
    JavaScriptBundle,
    SourceDirectory,
    SingleSourceFile,
    NativeBinary,
    WasmArtifact,
    AndroidApk,
    SqliteDatabase,
    PcapCapture,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineFinding {
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file: Option<String>,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineMetrics {
    pub total_files: usize,
    pub total_lines: usize,
    pub total_bytes: usize,
    pub total_functions: usize,
    pub total_classes: usize,
    pub total_symbols: usize,
    pub internal_dependencies: usize,
    pub unresolved_dependencies: usize,
    pub elapsed_ms: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct FindingsSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineReport {
    pub target_path: String,
    pub target_sha256: String,
    pub target_kind: TargetKind,
    pub overall_verdict: String,
    pub stages_executed: Vec<String>,
    pub staging_directory: Option<String>,
    pub recovered_modules_count: usize,
    pub extracted_sources_count: usize,
    pub fuse_report: Option<FuseReport>,
    pub findings_summary: FindingsSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_findings_path: Option<String>,
    pub findings: Vec<PipelineFinding>,
    pub metrics: PipelineMetrics,
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn is_supported_js_ts(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts")
    )
}

fn collect_js_files(root: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
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
        if entry.file_type().is_some_and(|t| t.is_file()) && is_supported_js_ts(entry.path()) {
            files.push(entry.into_path());
        }
    }
    files.sort();
    Ok(files)
}

pub struct AuditPipeline;

impl AuditPipeline {
    /// Detect target artifact kind
    pub fn detect_target(path: &Path) -> TargetKind {
        if path.is_dir() {
            return TargetKind::SourceDirectory;
        }

        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            match ext.to_lowercase().as_str() {
                "asar" => return TargetKind::AsarArchive,
                "map" => return TargetKind::SourceMap,
                "apk" => return TargetKind::AndroidApk,
                "wasm" => return TargetKind::WasmArtifact,
                "db" | "sqlite" | "sqlite3" => return TargetKind::SqliteDatabase,
                "pcap" | "pcapng" | "cap" => return TargetKind::PcapCapture,
                "js" | "mjs" | "cjs" => {
                    // Check if bundle or single source
                    if let Ok(content) = fs::read_to_string(path) {
                        if content.contains("webpackChunk")
                            || content.contains("__webpack_require__")
                            || content.contains("__commonJS")
                        {
                            return TargetKind::JavaScriptBundle;
                        }
                    }
                    return TargetKind::SingleSourceFile;
                }
                "ts" | "tsx" | "jsx" => return TargetKind::SingleSourceFile,
                _ => {}
            }
        }

        // Check magic bytes
        if let Ok(bytes) = fs::read(path) {
            if bytes.len() >= 4 && &bytes[..4] == b"\0asm" {
                return TargetKind::WasmArtifact;
            }
            if bytes.len() >= 16 && &bytes[..16] == b"SQLite format 3\0" {
                return TargetKind::SqliteDatabase;
            }
            if bytes.len() >= 4 {
                let magic4 = &bytes[..4];
                if magic4 == b"\xd4\xc3\xb2\xa1"
                    || magic4 == b"\xa1\xb2\xc3\xd4"
                    || magic4 == b"\x4d\x3c\xb2\xa1"
                    || magic4 == b"\xa1\xb2\x3c\x4d"
                    || magic4 == b"\x0a\x0d\x0d\x0a"
                {
                    return TargetKind::PcapCapture;
                }
            }
            if bytes.windows(32).any(|w| w == b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX") {
                return TargetKind::ElectronBinary;
            }
            if TauriScanner::detect_binary(&bytes).is_tauri {
                return TargetKind::TauriBinary;
            }
            // Check native binary headers: ELF, PE, Mach-O
            if bytes.starts_with(b"\x7fELF")
                || (bytes.len() >= 2 && &bytes[..2] == b"MZ")
                || (bytes.len() >= 4
                    && (bytes.starts_with(b"\xfe\xed\xfa\xce")
                        || bytes.starts_with(b"\xfe\xed\xfa\xcf")
                        || bytes.starts_with(b"\xce\xfa\xed\xfe")
                        || bytes.starts_with(b"\xcf\xfa\xed\xfe")
                        || bytes.starts_with(b"\xca\xfe\xba\xbe")))
            {
                return TargetKind::NativeBinary;
            }
        }

        TargetKind::Unknown
    }

    /// Run full automated audit pipeline on target
    pub fn run(
        target_path: &Path,
        custom_out_dir: Option<&Path>,
    ) -> Result<PipelineReport, Box<dyn Error>> {
        let start_time = Instant::now();
        let target_canonical = target_path.canonicalize()?;
        let target_sha256 = if target_canonical.is_file() {
            sha256_file(&target_canonical)?
        } else {
            "directory".to_string()
        };

        let target_kind = Self::detect_target(&target_canonical);
        let mut stages = Vec::new();
        let mut findings = Vec::new();
        let mut fuse_report = None;
        let mut recovered_modules_count = 0;
        let mut extracted_sources_count = 0;

        // Configure workspace / staging output dir
        let staging_dir = if let Some(out) = custom_out_dir {
            out.to_path_buf()
        } else {
            std::env::temp_dir().join(format!("rea_pipeline_{}", std::process::id()))
        };

        // 1. STAGE: De-packaging & Source Recovery
        let analysis_target_dir = match &target_kind {
            TargetKind::AsarArchive => {
                stages.push("asar-extraction".to_string());
                let extract_dest = staging_dir.join("unpacked_asar");
                let ext_res = asar::extract_artifact(
                    &target_canonical,
                    Some(&extract_dest),
                    IntegrityPolicy::RecordAndContinue,
                )?;
                if !ext_res.contradictions.is_empty() {
                    findings.push(PipelineFinding {
                        category: "integrity".to_string(),
                        severity: Severity::High,
                        title: "ASAR Checksum Mismatches Detected".to_string(),
                        description: format!(
                            "{} files failed SHA-256 integrity verification in archive",
                            ext_res.contradictions.len()
                        ),
                        file: Some(target_canonical.to_string_lossy().to_string()),
                        line: None,
                    });
                }
                extract_dest
            }
            TargetKind::JavaScriptBundle => {
                stages.push("bundle-recovery".to_string());
                let bundle_dest = staging_dir.join("recovered_modules");
                let recoverer =
                    SourceRecoverer::new(ExtractionMode::Structural, RewriteLevel::Standard);
                if let Ok(res) = recoverer.recover(&target_canonical, &bundle_dest) {
                    recovered_modules_count = res.recovered_modules.len();
                }

                // Check for sourcemap in bundle
                let sm_dest = staging_dir.join("sourcemap_sources");
                if let Ok(sm_res) = SourceMapExtractor::extract(&target_canonical, &sm_dest) {
                    extracted_sources_count = sm_res.extracted_files.len();
                    stages.push("sourcemap-reconstruction".to_string());
                }

                bundle_dest
            }
            TargetKind::SourceMap => {
                stages.push("sourcemap-reconstruction".to_string());
                let sm_dest = staging_dir.join("sourcemap_sources");
                let sm_res = SourceMapExtractor::extract(&target_canonical, &sm_dest)?;
                extracted_sources_count = sm_res.extracted_files.len();
                sm_dest
            }
            TargetKind::ElectronBinary => {
                stages.push("binary-fuse-inspection".to_string());
                let rep = fuses::inspect_fuses(&target_canonical)?;
                Self::audit_fuses(&rep, &mut findings);
                fuse_report = Some(rep);
                target_canonical.clone()
            }
            TargetKind::TauriBinary => {
                stages.push("tauri-binary-audit".to_string());
                let tauri_dest = staging_dir.join("tauri_extracted");
                let audit_res = TauriScanner::audit_path(&target_canonical, Some(&tauri_dest))?;
                extracted_sources_count += audit_res.extracted_files.len();
                for ipc in audit_res.ipc_findings {
                    findings.push(PipelineFinding {
                        category: "tauri-ipc".to_string(),
                        severity: Severity::Info,
                        title: format!("Tauri IPC {}: '{}'", ipc.kind, ipc.name),
                        description: format!("Found Tauri {} call in binary or embedded scripts", ipc.kind),
                        file: ipc.file,
                        line: Some(ipc.line),
                    });
                }
                if let Some(cfg) = audit_res.embedded_config {
                    findings.push(PipelineFinding {
                        category: "tauri-config".to_string(),
                        severity: Severity::Info,
                        title: "Tauri Embedded Config Recovered".to_string(),
                        description: format!("Extracted embedded configuration: {}", cfg),
                        file: Some(target_canonical.to_string_lossy().to_string()),
                        line: None,
                    });
                }
                if tauri_dest.exists() {
                    tauri_dest
                } else {
                    target_canonical.clone()
                }
            }
            TargetKind::SourceDirectory => {
                // If directory contains app.asar or fuses, check them
                let asar_candidate = target_canonical.join("resources").join("app.asar");
                if asar_candidate.exists() {
                    stages.push("asar-extraction".to_string());
                    let extract_dest = staging_dir.join("unpacked_asar");
                    let _ = asar::extract_artifact(
                        &asar_candidate,
                        Some(&extract_dest),
                        IntegrityPolicy::RecordAndContinue,
                    );
                }
                target_canonical.clone()
            }
            TargetKind::SingleSourceFile => {
                // Check if inline sourcemap exists
                let sm_dest = staging_dir.join("sourcemap_sources");
                if let Ok(sm_res) = SourceMapExtractor::extract(&target_canonical, &sm_dest) {
                    extracted_sources_count = sm_res.extracted_files.len();
                    stages.push("sourcemap-reconstruction".to_string());
                }
                target_canonical.clone()
            }
            TargetKind::AndroidApk => {
                stages.push("android-apk-audit".to_string());
                if let Ok(apk_info) = MobileInspector::inspect_apk(&target_canonical) {
                    Self::audit_android_apk(&apk_info, &mut findings);
                }
                target_canonical.clone()
            }
            TargetKind::NativeBinary => {
                stages.push("native-binary-audit".to_string());
                if let Ok(layout) = NativeInspector::inspect_layout(&target_canonical) {
                    Self::audit_native_layout(&layout, &mut findings);
                }
                if let Ok(go_info) = NativeInspector::inspect_go(&target_canonical) {
                    if go_info.has_go_buildinfo {
                        stages.push("go-buildinfo-audit".to_string());
                        Self::audit_go_buildinfo(&go_info, &target_canonical, &mut findings);
                    }
                }
                if let Ok(rust_info) = NativeInspector::inspect_rust(&target_canonical) {
                    if rust_info.has_rust_auditable {
                        stages.push("rust-auditable-audit".to_string());
                        Self::audit_rust_info(&rust_info, &target_canonical, &mut findings);
                    }
                }
                target_canonical.clone()
            }
            TargetKind::WasmArtifact => {
                stages.push("wasm-interface-audit".to_string());
                if let Ok(bytes) = fs::read(&target_canonical) {
                    let wasm = NativeInspector::inspect_wasm(&bytes);
                    Self::audit_wasm(&wasm, &target_canonical, &mut findings);
                }
                target_canonical.clone()
            }
            TargetKind::SqliteDatabase => {
                stages.push("sqlite-database-audit".to_string());
                if let Ok(db_info) = StoragePcapInspector::inspect_sqlite(&target_canonical) {
                    Self::audit_sqlite(&db_info, &mut findings);
                }
                target_canonical.clone()
            }
            TargetKind::PcapCapture => {
                stages.push("pcap-packet-audit".to_string());
                if let Ok(pcap_info) = StoragePcapInspector::inspect_pcap(&target_canonical) {
                    Self::audit_pcap(&pcap_info, &mut findings);
                }
                target_canonical.clone()
            }
            TargetKind::Unknown => target_canonical.clone(),
        };

        // 2. STAGE: AST Analysis & Dependency Graph
        stages.push("parallel-ast-analysis".to_string());
        let js_files = if analysis_target_dir.is_dir() {
            collect_js_files(&analysis_target_dir).unwrap_or_default()
        } else if is_supported_js_ts(&analysis_target_dir) {
            vec![analysis_target_dir.clone()]
        } else {
            Vec::new()
        };

        let pool = rayon::ThreadPoolBuilder::new().build()?;
        let file_analyses: Vec<FileAnalysis> = pool.install(|| {
            js_files
                .par_iter()
                .map(|p| {
                    analyze::analyze_file(
                        p,
                        if analysis_target_dir.is_file() {
                            analysis_target_dir.parent().unwrap_or(&analysis_target_dir)
                        } else {
                            &analysis_target_dir
                        },
                        16_777_216,
                    )
                })
                .collect()
        });

        let deps = graph::dependencies(&file_analyses);
        let mut total_lines = 0;
        let mut total_bytes = 0;
        let mut total_functions = 0;
        let mut total_classes = 0;
        let mut total_symbols = 0;

        for f in &file_analyses {
            total_lines += f.lines;
            total_bytes += f.bytes;
            total_functions += f.functions.len();
            total_classes += f.classes.len();
            total_symbols += f.symbols;
        }

        let internal_deps = deps.iter().flatten().filter(|d| d.target.is_some()).count();
        let unresolved_deps = deps.iter().flatten().filter(|d| d.target.is_none()).count();

        // 3. STAGE: Electron Security & IPC Auditing
        stages.push("electron-security-audit".to_string());
        for p in &js_files {
            if let Ok(source) = fs::read_to_string(p) {
                let el_findings =
                    electron::analyze_electron_source(&source, &p.to_string_lossy());
                Self::translate_electron_findings(&el_findings, p, &mut findings);
            }
        }

        // 4. STAGE: Secret Leak & API Endpoint Scanning
        stages.push("secrets-and-endpoints-scan".to_string());
        for p in &js_files {
            if let Ok(source) = fs::read_to_string(p) {
                let file_str = p.to_string_lossy().to_string();
                let secret_res = SecretScanner::scan_str(&source, Some(&file_str));
                for sec in secret_res.secrets {
                    let sev = match sec.severity.as_str() {
                        "CRITICAL" => Severity::Critical,
                        "HIGH" => Severity::High,
                        "MEDIUM" => Severity::Medium,
                        "LOW" => Severity::Low,
                        _ => Severity::Info,
                    };
                    findings.push(PipelineFinding {
                        category: "credential-leak".to_string(),
                        severity: sev,
                        title: format!("{}: {}", sec.rule, sec.matched_masked),
                        description: format!("High-entropy credential detected (SHA-256: {})", sec.sha256),
                        file: sec.file,
                        line: Some(sec.line),
                    });
                }
                for ep in secret_res.endpoints {
                    findings.push(PipelineFinding {
                        category: "api-endpoint".to_string(),
                        severity: Severity::Info,
                        title: format!("{}: {}", ep.kind, ep.url_or_path),
                        description: "Discovered exposed network URL or internal route".to_string(),
                        file: ep.file,
                        line: Some(ep.line),
                    });
                }
            }
        }

        // Calculate overall security verdict
        let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
        let has_high = findings.iter().any(|f| f.severity == Severity::High);
        let overall_verdict = if has_critical {
            "CRITICAL_RISKS_DETECTED".to_string()
        } else if has_high {
            "WARNING_ELEVATED_RISKS".to_string()
        } else {
            "SECURE_PASS".to_string()
        };

        let elapsed = start_time.elapsed().as_secs_f64();
        let metrics = PipelineMetrics {
            total_files: file_analyses.len(),
            total_lines,
            total_bytes,
            total_functions,
            total_classes,
            total_symbols,
            internal_dependencies: internal_deps,
            unresolved_dependencies: unresolved_deps,
            elapsed_ms: elapsed * 1000.0,
        };

        let mut findings_summary = FindingsSummary::default();
        findings_summary.total = findings.len();
        for f in &findings {
            match f.severity {
                Severity::Critical => findings_summary.critical += 1,
                Severity::High => findings_summary.high += 1,
                Severity::Medium => findings_summary.medium += 1,
                Severity::Low => findings_summary.low += 1,
                Severity::Info => findings_summary.info += 1,
            }
        }

        // Sort findings by severity: Critical > High > Medium > Low > Info
        findings.sort_by_key(|f| match f.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        });

        let mut full_findings_path = None;
        if findings.len() > 50 {
            let full_path = staging_dir.join("audit_findings_full.json");
            let _ = fs::create_dir_all(&staging_dir);
            if let Ok(file) = fs::File::create(&full_path) {
                let _ = serde_json::to_writer_pretty(file, &findings);
                full_findings_path = Some(full_path.to_string_lossy().to_string());
            }
            findings.truncate(50);
        }

        Ok(PipelineReport {
            target_path: target_canonical.to_string_lossy().to_string(),
            target_sha256,
            target_kind,
            overall_verdict,
            stages_executed: stages,
            staging_directory: if staging_dir.exists() {
                Some(staging_dir.to_string_lossy().to_string())
            } else {
                None
            },
            recovered_modules_count,
            extracted_sources_count,
            fuse_report,
            findings_summary,
            full_findings_path,
            findings,
            metrics,
        })
    }

    fn audit_fuses(rep: &FuseReport, findings: &mut Vec<PipelineFinding>) {
        for slice in &rep.slices {
            for fuse in &slice.fuses {
                if fuse.name == "RunAsNode" && fuse.state == FuseState::Enabled {
                    findings.push(PipelineFinding {
                        category: "fuse-hardening".to_string(),
                        severity: Severity::Critical,
                        title: "Electron Fuse 'RunAsNode' is Enabled".to_string(),
                        description: "ELECTRON_RUN_AS_NODE is active, allowing arbitrary Node.js code execution via environment variable.".to_string(),
                        file: Some(rep.path.clone()),
                        line: None,
                    });
                }
                if fuse.name == "EnableNodeCliInspectArguments" && fuse.state == FuseState::Enabled {
                    findings.push(PipelineFinding {
                        category: "fuse-hardening".to_string(),
                        severity: Severity::High,
                        title: "Electron Fuse 'EnableNodeCliInspectArguments' is Enabled".to_string(),
                        description: "Allows attaching Node.js remote inspect debugger (--inspect) to running application.".to_string(),
                        file: Some(rep.path.clone()),
                        line: None,
                    });
                }
                if fuse.name == "OnlyLoadAppFromAsar" && fuse.state == FuseState::Disabled {
                    findings.push(PipelineFinding {
                        category: "fuse-hardening".to_string(),
                        severity: Severity::Medium,
                        title: "Electron Fuse 'OnlyLoadAppFromAsar' is Disabled".to_string(),
                        description: "App allows loading unpacked script directories, making it vulnerable to local script tampering.".to_string(),
                        file: Some(rep.path.clone()),
                        line: None,
                    });
                }
            }
        }
    }

    fn translate_electron_findings(
        ef: &ElectronStaticFindings,
        path: &Path,
        findings: &mut Vec<PipelineFinding>,
    ) {
        let file_str = path.to_string_lossy().to_string();
        for bw in &ef.browser_windows {
            let wp = &bw.web_preferences;
            let line = Some(bw.location.start.line as usize);
            if wp.node_integration == Some(true) {
                findings.push(PipelineFinding {
                    category: "webPreferences".to_string(),
                    severity: Severity::Critical,
                    title: "nodeIntegration: true".to_string(),
                    description: "Renderer process has unrestricted access to Node.js primitives and filesystem.".to_string(),
                    file: Some(file_str.clone()),
                    line,
                });
            }
            if wp.context_isolation == Some(false) {
                findings.push(PipelineFinding {
                    category: "webPreferences".to_string(),
                    severity: Severity::High,
                    title: "contextIsolation: false".to_string(),
                    description: "Context isolation is disabled, exposing Electron APIs to untrusted website DOM scripts.".to_string(),
                    file: Some(file_str.clone()),
                    line,
                });
            }
            if wp.sandbox == Some(false) {
                findings.push(PipelineFinding {
                    category: "webPreferences".to_string(),
                    severity: Severity::Medium,
                    title: "sandbox: false".to_string(),
                    description: "Renderer Chromium sandbox is disabled.".to_string(),
                    file: Some(file_str.clone()),
                    line,
                });
            }
            if wp.web_security == Some(false) {
                findings.push(PipelineFinding {
                    category: "webPreferences".to_string(),
                    severity: Severity::Critical,
                    title: "webSecurity: false".to_string(),
                    description: "Same-origin policy disabled in renderer window.".to_string(),
                    file: Some(file_str.clone()),
                    line,
                });
            }
        }

        let has_sender_validation = !ef.sender_validations.is_empty();
        for ipc in &ef.ipc {
            if ipc.process == "main" && (ipc.operation == "on" || ipc.operation == "handle") {
                let channel_name = ipc.channel.as_deref().unwrap_or("<dynamic>");
                if !has_sender_validation {
                    findings.push(PipelineFinding {
                        category: "ipc".to_string(),
                        severity: Severity::Medium,
                        title: format!("IPC Channel '{}' without sender verification", channel_name),
                        description: "Main process listens on IPC channel without checking event.senderFrame origin.".to_string(),
                        file: Some(file_str.clone()),
                        line: Some(ipc.location.start.line as usize),
                    });
                }
            }
        }
    }

    fn audit_android_apk(apk: &AndroidPackageInfo, findings: &mut Vec<PipelineFinding>) {
        let file_opt = Some(apk.path.clone());
        if let Some(ref pkg) = apk.package_name {
            findings.push(PipelineFinding {
                category: "android-package".to_string(),
                severity: Severity::Info,
                title: format!("Package: {}", pkg),
                description: format!("Parsed package name from AndroidManifest.xml: {}", pkg),
                file: file_opt.clone(),
                line: None,
            });
        }
        for perm in &apk.permissions {
            let perm_lower = perm.to_lowercase();
            let (sev, desc) = if perm_lower.contains("record_audio")
                || perm_lower.contains("send_sms")
                || perm_lower.contains("read_sms")
                || perm_lower.contains("receive_sms")
                || perm_lower.contains("system_alert_window")
                || perm_lower.contains("write_settings")
            {
                (Severity::High, "Sensitive/dangerous system permission requested")
            } else if perm_lower.contains("camera")
                || perm_lower.contains("fine_location")
                || perm_lower.contains("read_contacts")
                || perm_lower.contains("write_external_storage")
            {
                (Severity::Medium, "Privileged resource access permission requested")
            } else {
                (Severity::Info, "Standard Android application permission")
            };
            findings.push(PipelineFinding {
                category: "android-permission".to_string(),
                severity: sev,
                title: format!("Permission: {}", perm),
                description: desc.to_string(),
                file: file_opt.clone(),
                line: None,
            });
        }
        if !apk.native_libraries.is_empty() {
            let abis: Vec<String> = apk.native_libraries.keys().cloned().collect();
            findings.push(PipelineFinding {
                category: "android-native".to_string(),
                severity: Severity::Info,
                title: format!("Native ABIs: {}", abis.join(", ")),
                description: format!("Discovered native C/C++ libraries across {} ABIs", abis.len()),
                file: file_opt,
                line: None,
            });
        }
    }

    fn audit_native_layout(layout: &BinaryLayout, findings: &mut Vec<PipelineFinding>) {
        let file_opt = Some(layout.path.clone());
        findings.push(PipelineFinding {
            category: "binary-info".to_string(),
            severity: Severity::Info,
            title: format!("Binary Format: {} ({})", layout.format, layout.architecture),
            description: format!(
                "Sections: {}, Symbols: {}, Entry: 0x{:x}, Imports: {}",
                layout.total_sections, layout.symbol_count, layout.entry_point, layout.imports.len()
            ),
            file: file_opt.clone(),
            line: None,
        });

        for imp in &layout.imports {
            let imp_lower = imp.to_lowercase();
            if imp_lower.contains("system")
                || imp_lower.contains("popen")
                || imp_lower.contains("execve")
                || imp_lower.contains("ptrace")
                || imp_lower.contains("virtualalloc")
                || imp_lower.contains("createremotethread")
                || imp_lower.contains("writeprocessmemory")
            {
                findings.push(PipelineFinding {
                    category: "risky-import".to_string(),
                    severity: Severity::Medium,
                    title: format!("Dangerous Native Import: {}", imp),
                    description: "Executable imports low-level execution/injection API".to_string(),
                    file: file_opt.clone(),
                    line: None,
                });
            }
        }
    }

    fn audit_go_buildinfo(go: &GoBuildInfo, path: &Path, findings: &mut Vec<PipelineFinding>) {
        let file_str = path.to_string_lossy().to_string();
        if let Some(ref v) = go.go_version {
            findings.push(PipelineFinding {
                category: "go-compiler".to_string(),
                severity: Severity::Info,
                title: format!("Go Compiler: {}", v),
                description: format!("Embedded Go build version: {}", v),
                file: Some(file_str.clone()),
                line: None,
            });
        }
        if let Some(ref m) = go.main_module {
            findings.push(PipelineFinding {
                category: "go-module".to_string(),
                severity: Severity::Info,
                title: format!("Go Main Module: {}", m),
                description: format!("Dependencies embedded: {}", go.raw_deps.len()),
                file: Some(file_str),
                line: None,
            });
        }
    }

    fn audit_rust_info(rust: &RustBinaryInfo, path: &Path, findings: &mut Vec<PipelineFinding>) {
        let file_str = path.to_string_lossy().to_string();
        if let Some(ref commit) = rust.rustc_commit {
            findings.push(PipelineFinding {
                category: "rustc-compiler".to_string(),
                severity: Severity::Info,
                title: format!("Rustc Commit: {}", commit),
                description: format!("Source build commit: https://github.com/rust-lang/rust/commit/{}", commit),
                file: Some(file_str.clone()),
                line: None,
            });
        }
        if rust.has_rust_auditable {
            findings.push(PipelineFinding {
                category: "cargo-auditable".to_string(),
                severity: Severity::Info,
                title: "Cargo Auditable Dependency Bill-of-Materials Present".to_string(),
                description: "Embedded .dep-v0 section contains complete verifiable dependency tree".to_string(),
                file: Some(file_str),
                line: None,
            });
        }
    }

    fn audit_wasm(wasm: &WasmInterface, path: &Path, findings: &mut Vec<PipelineFinding>) {
        let file_str = path.to_string_lossy().to_string();
        findings.push(PipelineFinding {
            category: "wasm-interface".to_string(),
            severity: Severity::Info,
            title: format!("WebAssembly Module (v{})", wasm.version),
            description: format!(
                "Sections: {}, Imports: {}, Exports: {}",
                wasm.sections.len(), wasm.imports.len(), wasm.exports.len()
            ),
            file: Some(file_str),
            line: None,
        });
    }

    fn audit_sqlite(db: &SqliteDbInfo, findings: &mut Vec<PipelineFinding>) {
        let file_opt = Some(db.path.clone());
        findings.push(PipelineFinding {
            category: "sqlite-db".to_string(),
            severity: Severity::Info,
            title: format!("SQLite Database: {} tables", db.total_tables),
            description: format!(
                "Page size: {} bytes, user_version: {}, schema_cookie: {}, changes: {}",
                db.page_size, db.user_version, db.schema_cookie, db.change_counter
            ),
            file: file_opt.clone(),
            line: None,
        });
        for tbl in &db.tables {
            let name_lower = tbl.name.to_lowercase();
            if name_lower.contains("user")
                || name_lower.contains("pass")
                || name_lower.contains("auth")
                || name_lower.contains("token")
                || name_lower.contains("secret")
                || name_lower.contains("cred")
                || name_lower.contains("key")
                || name_lower.contains("session")
            {
                findings.push(PipelineFinding {
                    category: "sqlite-sensitive-data".to_string(),
                    severity: Severity::Medium,
                    title: format!("Sensitive Table Identified: '{}'", tbl.name),
                    description: format!("Database contains '{}' table storing credentials or auth data", tbl.name),
                    file: file_opt.clone(),
                    line: None,
                });
            }
        }
    }

    fn audit_pcap(pcap: &PcapCaptureInfo, findings: &mut Vec<PipelineFinding>) {
        let file_opt = Some(pcap.path.clone());
        findings.push(PipelineFinding {
            category: "pcap-capture".to_string(),
            severity: Severity::Info,
            title: format!("Network Capture: {} ({} packets, {} bytes)", pcap.format, pcap.total_packets, pcap.total_bytes),
            description: format!(
                "Protocols: {}, Unique IPs: {}, Unique Ports: {}",
                pcap.protocols.join(", "), pcap.unique_ips.len(), pcap.unique_ports.len()
            ),
            file: file_opt.clone(),
            line: None,
        });

        if pcap.unique_ports.contains(&80) || pcap.unique_ports.contains(&23) || pcap.unique_ports.contains(&21) {
            findings.push(PipelineFinding {
                category: "cleartext-traffic".to_string(),
                severity: Severity::Medium,
                title: "Cleartext Protocol Traffic Observed".to_string(),
                description: "Capture contains packets routed through unencrypted ports (HTTP 80, Telnet 23, or FTP 21)".to_string(),
                file: file_opt,
                line: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_target_kinds() {
        assert!(matches!(
            AuditPipeline::detect_target(Path::new("app.asar")),
            TargetKind::AsarArchive
        ));
        assert!(matches!(
            AuditPipeline::detect_target(Path::new("test.map")),
            TargetKind::SourceMap
        ));
        assert!(matches!(
            AuditPipeline::detect_target(Path::new(".")),
            TargetKind::SourceDirectory
        ));
    }

    #[test]
    fn test_pipeline_on_single_file_with_secrets() {
        let temp_dir = std::env::temp_dir().join("rea_test_pipeline");
        let _ = fs::create_dir_all(&temp_dir);
        let src_file = temp_dir.join("vuln.js");
        let content = r#"
            const aws = "AKIA1234567890ABCDEF";
            const api = "https://api.internal.corp/v1/auth";
            const win = new BrowserWindow({
                webPreferences: {
                    nodeIntegration: true,
                    contextIsolation: false
                }
            });
        "#;
        fs::write(&src_file, content).unwrap();

        let report = AuditPipeline::run(&src_file, None).unwrap();
        assert_eq!(report.overall_verdict, "CRITICAL_RISKS_DETECTED");
        assert!(report.stages_executed.contains(&"secrets-and-endpoints-scan".to_string()));
        assert!(report.findings.iter().any(|f| f.category == "credential-leak"));
        assert!(report.findings.iter().any(|f| f.category == "api-endpoint"));
        assert!(report.findings.iter().any(|f| f.category == "webPreferences"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
