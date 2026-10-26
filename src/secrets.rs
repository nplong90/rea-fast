use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path, sync::LazyLock};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecretFinding {
    pub rule: String,
    pub severity: String,
    pub file: Option<String>,
    pub line: usize,
    pub matched_masked: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EndpointFinding {
    pub url_or_path: String,
    pub kind: String,
    pub file: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SecretScanResult {
    pub secrets: Vec<SecretFinding>,
    pub endpoints: Vec<EndpointFinding>,
    pub total_secrets: usize,
    pub total_endpoints: usize,
}

struct SecretPattern {
    rule: &'static str,
    severity: &'static str,
    pattern: &'static str,
}

static PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        rule: "AWS Access Key",
        severity: "CRITICAL",
        pattern: r"\b(AKIA[0-9A-Z]{16})\b",
    },
    SecretPattern {
        rule: "Google / Firebase API Key",
        severity: "HIGH",
        pattern: r"\b(AIza[0-9A-Za-z\-_]{35})\b",
    },
    SecretPattern {
        rule: "GitHub Token",
        severity: "CRITICAL",
        pattern: r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b",
    },
    SecretPattern {
        rule: "Slack Token",
        severity: "HIGH",
        pattern: r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b",
    },
    SecretPattern {
        rule: "Stripe Secret Key",
        severity: "CRITICAL",
        pattern: r"\b([sr]k_live_[0-9a-zA-Z]{24,99})\b",
    },
    SecretPattern {
        rule: "Private Key",
        severity: "CRITICAL",
        pattern: r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----",
    },
    SecretPattern {
        rule: "JSON Web Token (JWT)",
        severity: "MEDIUM",
        pattern: r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
    },
];

static COMPILED_PATTERNS: LazyLock<Vec<(&'static SecretPattern, Regex)>> = LazyLock::new(|| {
    PATTERNS
        .iter()
        .map(|p| (p, Regex::new(p.pattern).unwrap()))
        .collect()
});

static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\s"'`<>]+)?"#).unwrap()
});

static API_ROUTE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'`]/(api|v[0-9]+|auth|graphql|rest|ws)/([a-zA-Z0-9_./-]+)["'`]"#).unwrap()
});

pub fn mask_secret(val: &str) -> String {
    let len = val.len();
    if len <= 8 {
        return "*".repeat(len);
    }
    let prefix = &val[..4];
    let suffix = &val[len - 4..];
    format!("{}...{}", prefix, suffix)
}

fn sha256_hex(val: &str) -> String {
    format!("{:x}", Sha256::digest(val.as_bytes()))
}

pub struct SecretScanner;

impl SecretScanner {
    pub fn scan_str(content: &str, file_path: Option<&str>) -> SecretScanResult {
        let mut secrets = Vec::new();
        let mut endpoints = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;

            // 1. Secrets
            for (pat, re) in COMPILED_PATTERNS.iter() {
                for mat in re.find_iter(line) {
                    let matched_str = mat.as_str();
                    secrets.push(SecretFinding {
                        rule: pat.rule.to_string(),
                        severity: pat.severity.to_string(),
                        file: file_path.map(|s| s.to_string()),
                        line: line_num,
                        matched_masked: mask_secret(matched_str),
                        sha256: sha256_hex(matched_str),
                    });
                }
            }

            // 2. URLs
            for mat in URL_REGEX.find_iter(line) {
                let url = mat.as_str().trim_end_matches(&[',', ';', ')', '}', ']'][..]);
                endpoints.push(EndpointFinding {
                    url_or_path: url.to_string(),
                    kind: "absolute_url".to_string(),
                    file: file_path.map(|s| s.to_string()),
                    line: line_num,
                });
            }

            // 3. API Routes
            for caps in API_ROUTE_REGEX.captures_iter(line) {
                if let (Some(m1), Some(m2)) = (caps.get(1), caps.get(2)) {
                    endpoints.push(EndpointFinding {
                        url_or_path: format!("/{}/{}", m1.as_str(), m2.as_str()),
                        kind: "api_route".to_string(),
                        file: file_path.map(|s| s.to_string()),
                        line: line_num,
                    });
                }
            }
        }

        // Deduplicate endpoints by path + file
        endpoints.sort_by(|a, b| a.url_or_path.cmp(&b.url_or_path));
        endpoints.dedup_by(|a, b| a.url_or_path == b.url_or_path && a.file == b.file);

        let total_secrets = secrets.len();
        let total_endpoints = endpoints.len();

        SecretScanResult {
            secrets,
            endpoints,
            total_secrets,
            total_endpoints,
        }
    }

    pub fn scan_file(path: &Path) -> Result<SecretScanResult, Box<dyn Error>> {
        let content = fs::read_to_string(path)?;
        Ok(Self::scan_str(&content, Some(&path.to_string_lossy())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_and_google_keys() {
        let sample = "const aws = 'AKIA1234567890ABCDEF';\nconst g = 'AIzaSyA12345678901234567890123456789012';";
        let res = SecretScanner::scan_str(sample, Some("config.js"));
        assert_eq!(res.total_secrets, 2);
        assert_eq!(res.secrets[0].rule, "AWS Access Key");
        assert_eq!(res.secrets[0].matched_masked, "AKIA...CDEF");
        assert_eq!(res.secrets[1].rule, "Google / Firebase API Key");
    }

    #[test]
    fn detects_endpoints() {
        let sample = r#"
            const api = "https://api.example.com/v1/users";
            fetch('/api/v2/auth/login');
        "#;
        let res = SecretScanner::scan_str(sample, None);
        assert_eq!(res.total_endpoints, 2);
        assert!(res.endpoints.iter().any(|e| e.url_or_path == "https://api.example.com/v1/users"));
        assert!(res.endpoints.iter().any(|e| e.url_or_path == "/api/v2/auth/login"));
    }
}
