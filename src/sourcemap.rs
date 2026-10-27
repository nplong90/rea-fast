use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Write,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMapV3 {
    pub version: u32,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(rename = "sourceRoot", default)]
    pub source_root: Option<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(rename = "sourcesContent", default)]
    pub sources_content: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub mappings: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedSource {
    pub source_path: String,
    pub relative_path: String,
    pub size_bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMapExtractResult {
    pub map_file: String,
    pub output_directory: String,
    pub extracted_files: Vec<ExtractedSource>,
    pub total_files: usize,
    pub total_bytes: usize,
    pub warnings: Vec<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Simple standard Base64 decoder without external dependencies
pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &b) in TABLE.iter().enumerate() {
        lookup[b as usize] = i as u8;
    }

    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace() && b != b'=')
        .collect();

    let mut output = Vec::with_capacity((clean.len() * 3) / 4);
    let mut i = 0;
    while i < clean.len() {
        let b0 = lookup[clean[i] as usize];
        if b0 == 255 {
            return Err("Invalid base64 character".into());
        }
        if i + 1 >= clean.len() {
            break;
        }
        let b1 = lookup[clean[i + 1] as usize];
        if b1 == 255 {
            return Err("Invalid base64 character".into());
        }
        output.push((b0 << 2) | (b1 >> 4));

        if i + 2 < clean.len() {
            let b2 = lookup[clean[i + 2] as usize];
            if b2 == 255 {
                return Err("Invalid base64 character".into());
            }
            output.push(((b1 & 0x0f) << 4) | (b2 >> 2));

            if i + 3 < clean.len() {
                let b3 = lookup[clean[i + 3] as usize];
                if b3 == 255 {
                    return Err("Invalid base64 character".into());
                }
                output.push(((b2 & 0x03) << 6) | b3);
            }
        }
        i += 4;
    }

    Ok(output)
}

/// Sanitize source map paths: remove webpack://, file://, ../ traversal
pub fn sanitize_source_path(raw: &str, index: usize) -> PathBuf {
    let mut clean = raw.trim().replace('\\', "/");

    // Strip common URI schemes
    if let Some(pos) = clean.find("://") {
        clean = clean[pos + 3..].to_string();
    }

    // Strip leading webpack-relative markers
    clean = clean
        .trim_start_matches("./")
        .trim_start_matches('/')
        .trim_start_matches("~/")
        .to_string();

    let mut path = PathBuf::new();
    for comp in Path::new(&clean).components() {
        // Discard CurDir, ParentDir (..) to prevent path traversal.
        if let Component::Normal(c) = comp {
            path.push(c);
        }
    }

    if path.as_os_str().is_empty() {
        PathBuf::from(format!("sources/source_{}.js", index))
    } else {
        path
    }
}

pub struct SourceMapExtractor;

impl SourceMapExtractor {
    /// Extract all sourcesContent from a .map file or raw JSON content into output_directory
    pub fn extract_from_json(
        json_str: &str,
        origin_path: &str,
        output_dir: &Path,
    ) -> Result<SourceMapExtractResult, Box<dyn std::error::Error>> {
        let sm: SourceMapV3 = serde_json::from_str(json_str)?;
        let mut warnings = Vec::new();
        let mut extracted_files = Vec::new();
        let mut total_bytes = 0;

        fs::create_dir_all(output_dir)?;

        if let Some(contents) = &sm.sources_content {
            for (idx, source_path) in sm.sources.iter().enumerate() {
                let maybe_content = contents.get(idx).and_then(|c| c.as_ref());
                let content_str = match maybe_content {
                    Some(s) => s.as_str(),
                    None => {
                        warnings.push(format!("No sourcesContent for source: {}", source_path));
                        continue;
                    }
                };

                let rel_path = sanitize_source_path(source_path, idx);
                let target_path = output_dir.join(&rel_path);

                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                let bytes = content_str.as_bytes();
                let hash = sha256_hex(bytes);
                let size = bytes.len();
                total_bytes += size;

                let mut f = File::create(&target_path)?;
                f.write_all(bytes)?;

                extracted_files.push(ExtractedSource {
                    source_path: source_path.clone(),
                    relative_path: rel_path.to_string_lossy().replace('\\', "/"),
                    size_bytes: size,
                    sha256: hash,
                });
            }
        } else {
            warnings.push("Source map contains no 'sourcesContent' field".to_string());
        }

        Ok(SourceMapExtractResult {
            map_file: origin_path.to_string(),
            output_directory: output_dir.to_string_lossy().to_string(),
            total_files: extracted_files.len(),
            total_bytes,
            extracted_files,
            warnings,
        })
    }

    /// Extract from a file path (can be .map or .js containing inline sourceMappingURL)
    pub fn extract(
        input_path: &Path,
        output_dir: &Path,
    ) -> Result<SourceMapExtractResult, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(input_path)?;

        // Case 1: Direct JSON map
        if (input_path.extension().and_then(|s| s.to_str()) == Some("map")
            || content.trim_start().starts_with('{'))
            && let Ok(res) =
                Self::extract_from_json(&content, &input_path.to_string_lossy(), output_dir)
        {
            return Ok(res);
        }

        // Case 2: Inline Base64 Data URI in JS/TS: //# sourceMappingURL=data:application/json;base64,...
        if let Some(data_pos) = content.find("sourceMappingURL=data:application/json") {
            let rest = &content[data_pos..];
            if let Some(b64_pos) = rest.find("base64,") {
                let b64_data = &rest[b64_pos + 7..];
                let b64_end = b64_data
                    .find(|c: char| c.is_whitespace() || c == '*' || c == '/')
                    .unwrap_or(b64_data.len());
                let b64_str = &b64_data[..b64_end];

                match decode_base64(b64_str) {
                    Ok(decoded_bytes) => {
                        let json_str = String::from_utf8(decoded_bytes)?;
                        return Self::extract_from_json(
                            &json_str,
                            &format!("{}:inline", input_path.display()),
                            output_dir,
                        );
                    }
                    Err(err) => {
                        return Err(format!("Failed to decode inline base64 map: {}", err).into());
                    }
                }
            }
        }

        // Case 3: External map file referenced in //# sourceMappingURL=<filename>.map
        if let Some(idx) = content.rfind("sourceMappingURL=") {
            let line = &content[idx + 17..];
            let map_name = line
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches("*/")
                .trim();
            if !map_name.is_empty() && !map_name.starts_with("data:") {
                let map_path = input_path.parent().unwrap_or(Path::new(".")).join(map_name);
                if map_path.exists() {
                    let map_content = fs::read_to_string(&map_path)?;
                    return Self::extract_from_json(
                        &map_content,
                        &map_path.to_string_lossy(),
                        output_dir,
                    );
                }
            }
        }

        Err(format!("No valid source map found in {}", input_path.display()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sourcemap_v3_json() {
        let sample_map = r#"{
            "version": 3,
            "file": "bundle.js",
            "sources": ["webpack://app/src/index.ts", "webpack://app/src/utils/math.ts"],
            "sourcesContent": [
                "export const app = 'test';",
                "export function add(a: number, b: number) { return a + b; }"
            ],
            "names": [],
            "mappings": ""
        }"#;

        let temp_dir = std::env::temp_dir().join("rea_fast_sm_test");
        let _ = fs::remove_dir_all(&temp_dir);
        let out_dir = temp_dir.join("sources");

        let res = SourceMapExtractor::extract_from_json(sample_map, "test.map", &out_dir).unwrap();

        assert_eq!(res.total_files, 2);
        assert!(out_dir.join("app/src/index.ts").exists());
        assert!(out_dir.join("app/src/utils/math.ts").exists());

        let content = fs::read_to_string(out_dir.join("app/src/utils/math.ts")).unwrap();
        assert!(content.contains("export function add"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn decodes_base64_correctly() {
        let input = "SGVsbG8gV29ybGQ="; // "Hello World"
        let decoded = decode_base64(input).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }
}
