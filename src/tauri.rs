use crate::security_io::{self, MAX_ANALYSIS_FILE_BYTES};
use regex::Regex;
use serde::Serialize;
use std::io::Read;
use std::{error::Error, path::Path, sync::LazyLock};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TauriInfo {
    pub is_tauri: bool,
    pub version: Option<String>,
    pub framework_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TauriIpcFinding {
    pub kind: String, // "invoke", "listen", "emit"
    pub name: String,
    pub file: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TauriAuditResult {
    pub info: Option<TauriInfo>,
    pub embedded_config: Option<serde_json::Value>,
    pub extracted_files: Vec<String>,
    pub ipc_findings: Vec<TauriIpcFinding>,
    pub total_ipc_commands: usize,
}

static INVOKE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:invoke|__TAURI_INVOKE__)\s*\(\s*["']([a-zA-Z0-9_:-]+)["']"#).unwrap()
});

static LISTEN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:listen|__TAURI_LISTEN__)\s*\(\s*["']([a-zA-Z0-9_:-]+)["']"#).unwrap()
});

static EMIT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:emit|__TAURI_EMIT__)\s*\(\s*["']([a-zA-Z0-9_:-]+)["']"#).unwrap()
});

pub struct TauriScanner;

impl TauriScanner {
    pub fn detect_binary(bytes: &[u8]) -> TauriInfo {
        let hay = String::from_utf8_lossy(bytes);
        let mut signals = Vec::new();

        if hay.contains("__TAURI__") || hay.contains("window.__TAURI__") {
            signals.push("__TAURI__ global".into());
        }
        if hay.contains("tauri_runtime") || hay.contains("tauri::app") {
            signals.push("tauri_core_symbols".into());
        }
        if hay.contains("wry::webview") || hay.contains("tao::window") {
            signals.push("wry_tao_symbols".into());
        }

        let is_tauri = !signals.is_empty();
        let version = if !is_tauri {
            None
        } else if hay.contains("tauri_plugin") || hay.contains("AppHandle") {
            Some("v2".into())
        } else if hay.contains("tauri_runtime_wry") || hay.contains("tauri::app::App") {
            Some("v1".into())
        } else {
            Some("unknown".into())
        };

        TauriInfo {
            is_tauri,
            version,
            framework_signals: signals,
        }
    }

    pub fn extract_config(bytes: &[u8]) -> Option<serde_json::Value> {
        let text = String::from_utf8_lossy(bytes);
        // Find embedded tauri.conf.json snippets
        let mut idx = 0;
        while let Some(start) = text[idx..].find(r#"{"tauri""#) {
            let abs_start = idx + start;
            if let Some(cfg) = Self::try_parse_json_slice(&text[abs_start..]) {
                return Some(cfg);
            }
            idx = abs_start + 8;
        }
        idx = 0;
        while let Some(start) = text[idx..].find(r#"{"build""#) {
            let abs_start = idx + start;
            if let Some(cfg) = Self::try_parse_json_slice(&text[abs_start..])
                && (cfg.get("tauri").is_some() || cfg.get("bundle").is_some())
            {
                return Some(cfg);
            }
            idx = abs_start + 8;
        }
        None
    }

    fn try_parse_json_slice(slice: &str) -> Option<serde_json::Value> {
        // Find matching balanced braces
        let mut depth = 0;
        let mut end = 0;
        let mut in_str = false;
        let mut escaped = false;

        for (i, c) in slice.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            match c {
                '\\' if in_str => escaped = true,
                '"' => in_str = !in_str,
                '{' if !in_str => {
                    depth += 1;
                }
                '}' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }

        if end > 0 {
            serde_json::from_str(&slice[..end]).ok()
        } else {
            None
        }
    }

    pub fn extract_embedded_assets(
        bytes: &[u8],
        out_dir: &Path,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        security_io::create_private_output_directory(out_dir)?;
        let mut extracted = Vec::new();
        let text = String::from_utf8_lossy(bytes);

        // Scan for HTML documents
        let mut idx = 0;
        let mut html_count = 0;
        while let Some(pos) = text[idx..].find("<!DOCTYPE html>") {
            let start = idx + pos;
            if let Some(end_tag) = text[start..].find("</html>") {
                let end = start + end_tag + 7;
                let html_content = &text[start..end];
                let file_name = if html_count == 0 {
                    "index.html".to_string()
                } else {
                    format!("page_{}.html", html_count)
                };
                let out_file = out_dir.join(&file_name);
                std::io::Write::write_all(
                    &mut security_io::create_new_file(&out_file)?,
                    html_content.as_bytes(),
                )?;
                extracted.push(file_name);
                html_count += 1;
                idx = end;
            } else {
                idx = start + 15;
            }
        }

        // Try decompressing candidate brotli sections
        // ponytail: scans magic/heuristic headers if uncompressed html is absent, add deep ELF segment walker when needed.
        if extracted.is_empty() {
            let mut cursor = 0;
            let mut chunk_id = 0;
            while cursor + 4 < bytes.len() {
                // Heuristic probe for brotli decompressed asset
                let mut decompressed = Vec::new();
                let sub = &bytes[cursor..std::cmp::min(cursor + 512 * 1024, bytes.len())];
                let mut decoder = brotli::Decompressor::new(std::io::Cursor::new(sub), 4096);
                if (&mut decoder)
                    .take(16 * 1024 * 1024 + 1)
                    .read_to_end(&mut decompressed)
                    .is_ok()
                    && decompressed.len() <= 16 * 1024 * 1024
                    && (decompressed.starts_with(b"<!DOCTYPE html>")
                        || decompressed.starts_with(b"<html"))
                {
                    let file_name = format!("brotli_decompressed_{}.html", chunk_id);
                    std::io::Write::write_all(
                        &mut security_io::create_new_file(&out_dir.join(&file_name))?,
                        &decompressed,
                    )?;
                    extracted.push(file_name);
                    chunk_id += 1;
                    cursor += sub.len();
                    continue;
                }
                cursor += 4096;
            }
        }

        Ok(extracted)
    }

    pub fn scan_ipc(content: &str, file: Option<&str>) -> Vec<TauriIpcFinding> {
        let mut findings = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;

            for cap in INVOKE_REGEX.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    findings.push(TauriIpcFinding {
                        kind: "invoke".to_string(),
                        name: m.as_str().to_string(),
                        file: file.map(|s| s.to_string()),
                        line: line_num,
                    });
                }
            }

            for cap in LISTEN_REGEX.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    findings.push(TauriIpcFinding {
                        kind: "listen".to_string(),
                        name: m.as_str().to_string(),
                        file: file.map(|s| s.to_string()),
                        line: line_num,
                    });
                }
            }

            for cap in EMIT_REGEX.captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    findings.push(TauriIpcFinding {
                        kind: "emit".to_string(),
                        name: m.as_str().to_string(),
                        file: file.map(|s| s.to_string()),
                        line: line_num,
                    });
                }
            }
        }

        findings.sort_by(|a, b| (&a.kind, &a.name).cmp(&(&b.kind, &b.name)));
        findings.dedup();
        findings
    }

    pub fn audit_path(
        path: &Path,
        extract_to: Option<&Path>,
    ) -> Result<TauriAuditResult, Box<dyn Error>> {
        let bytes = security_io::read_limited(path, MAX_ANALYSIS_FILE_BYTES)?;
        let info = Self::detect_binary(&bytes);
        let config = Self::extract_config(&bytes);
        let extracted_files = if let Some(out) = extract_to {
            Self::extract_embedded_assets(&bytes, out)?
        } else {
            Vec::new()
        };

        let text = String::from_utf8_lossy(&bytes);
        let ipc_findings = Self::scan_ipc(&text, Some(&path.to_string_lossy()));
        let total = ipc_findings.len();

        Ok(TauriAuditResult {
            info: Some(info),
            embedded_config: config,
            extracted_files,
            ipc_findings,
            total_ipc_commands: total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_tauri_and_ipc() {
        let sample = r#"
            // Mock Tauri binary section
            const _sig = "window.__TAURI__ tauri::app tauri_plugin";
            invoke('get_user_info');
            listen('system_event', (e) => {});
            emit('user_login', { id: 1 });
        "#;
        let info = TauriScanner::detect_binary(sample.as_bytes());
        assert!(info.is_tauri);
        assert_eq!(info.version.as_deref(), Some("v2"));

        let findings = TauriScanner::scan_ipc(sample, Some("app.js"));
        assert_eq!(findings.len(), 3);
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "invoke" && f.name == "get_user_info")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "listen" && f.name == "system_event")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.kind == "emit" && f.name == "user_login")
        );
    }

    #[test]
    fn test_extract_config() {
        let sample = br#"random_junk_bytes{"tauri":{"windows":[{"title":"App"}]}}more_junk"#;
        let cfg = TauriScanner::extract_config(sample);
        assert!(cfg.is_some());
        let val = cfg.unwrap();
        assert_eq!(val["tauri"]["windows"][0]["title"], "App");
    }
}
