use crate::security_io::{self, MAX_SOURCE_FILE_BYTES};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrayExpressionElement, CallExpression, Declaration, Expression, ObjectPropertyKind,
    PropertyKey, Statement,
};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::{SourceType, Span};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fs;
use std::{
    io::Write,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum ExtractionMode {
    #[default]
    Structural,
    Heuristic,
    Inspection,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum RewriteLevel {
    #[default]
    Minimal,
    Standard,
    Aggressive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredModule {
    pub original_id: String,
    pub relative_path: String,
    pub byte_start: u32,
    pub byte_end: u32,
    pub size: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverSourcesResult {
    pub bundler: String,
    pub extraction_mode: ExtractionMode,
    pub rewrite_level: RewriteLevel,
    pub original_sha256: String,
    pub output_directory: String,
    pub recovered_modules: Vec<RecoveredModule>,
    pub warnings: Vec<String>,
    pub analysis_input: String,
}

pub struct SourceRecoverer {
    mode: ExtractionMode,
    rewrite: RewriteLevel,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sanitize_module_path(id: &str, index: usize) -> PathBuf {
    let clean = id
        .trim_start_matches("./")
        .trim_start_matches('/')
        .replace('\\', "/");

    let is_numeric = !clean.is_empty() && clean.chars().all(|c| c.is_ascii_digit());

    let mut path = PathBuf::new();
    for part in Path::new(&clean).components() {
        if let Component::Normal(s) = part {
            path.push(s)
        }
    }

    if path.as_os_str().is_empty() {
        PathBuf::from(format!("modules/{}.js", index))
    } else if is_numeric {
        PathBuf::from(format!("modules/{}.js", clean))
    } else {
        if path.extension().is_none() {
            path.set_extension("js");
        }
        path
    }
}

fn extract_function_body_from_expr(expr: &Expression<'_>) -> Option<Span> {
    let mut current = expr;
    while let Expression::ParenthesizedExpression(p) = current {
        current = &p.expression;
    }
    match current {
        Expression::FunctionExpression(f) => f.body.as_ref().map(|b| b.span),
        Expression::ArrowFunctionExpression(f) => Some(f.body.span),
        _ => None,
    }
}

fn extract_function_body_from_element(elem: &ArrayExpressionElement<'_>) -> Option<Span> {
    match elem {
        ArrayExpressionElement::FunctionExpression(f) => f.body.as_ref().map(|b| b.span),
        ArrayExpressionElement::ArrowFunctionExpression(f) => Some(f.body.span),
        ArrayExpressionElement::ParenthesizedExpression(p) => {
            extract_function_body_from_expr(&p.expression)
        }
        _ => elem
            .as_expression()
            .and_then(extract_function_body_from_expr),
    }
}

struct RawModule {
    id: String,
    body_span: Span,
}

impl SourceRecoverer {
    pub fn new(mode: ExtractionMode, rewrite: RewriteLevel) -> Self {
        Self { mode, rewrite }
    }

    pub fn recover(
        &self,
        input_path: &Path,
        output_directory: &Path,
    ) -> Result<RecoverSourcesResult, Box<dyn std::error::Error>> {
        if output_directory.exists() {
            return Err(format!(
                "Output directory already exists: {}",
                output_directory.display()
            )
            .into());
        }

        let parent = output_directory
            .parent()
            .ok_or("Invalid output directory parent")?;
        if !parent.exists() {
            return Err(format!("Parent directory does not exist: {}", parent.display()).into());
        }

        let source = security_io::read_string_limited(input_path, MAX_SOURCE_FILE_BYTES)?;
        let original_sha256 = sha256_hex(source.as_bytes());

        let (bundler, raw_modules, mut warnings) =
            self.detect_and_extract_modules(&source, input_path);

        let output = security_io::ExtractionRoot::create(output_directory)?;

        let mut recovered = Vec::new();

        for (idx, raw) in raw_modules.iter().enumerate() {
            let rel_path = sanitize_module_path(&raw.id, idx);

            let start = raw.body_span.start as usize;
            let end = raw.body_span.end as usize;

            let extracted_code = if start < source.len() && end <= source.len() && start < end {
                let slice = &source[start..end];
                self.process_code(slice)
            } else {
                warnings.push(format!(
                    "Module {} had invalid span {}..{}",
                    raw.id, start, end
                ));
                String::new()
            };

            let bytes = extracted_code.as_bytes();
            let hash = sha256_hex(bytes);
            let size = bytes.len();

            let mut f = output.create_new_file(&rel_path)?;
            f.write_all(bytes)?;

            recovered.push(RecoveredModule {
                original_id: raw.id.clone(),
                relative_path: rel_path.to_string_lossy().replace('\\', "/"),
                byte_start: raw.body_span.start,
                byte_end: raw.body_span.end,
                size,
                sha256: hash,
            });
        }

        let manifest_path = output_directory.join("manifest.json");
        let result = RecoverSourcesResult {
            bundler,
            extraction_mode: self.mode,
            rewrite_level: self.rewrite,
            original_sha256,
            output_directory: output_directory.to_string_lossy().to_string(),
            recovered_modules: recovered,
            warnings,
            analysis_input: manifest_path.to_string_lossy().to_string(),
        };

        let manifest_bytes = serde_json::to_vec_pretty(&result)?;
        let mut mf = output.create_new_file(Path::new("manifest.json"))?;
        mf.write_all(&manifest_bytes)?;

        Ok(result)
    }

    fn process_code(&self, code: &str) -> String {
        let trimmed = code.trim();
        if self.mode == ExtractionMode::Inspection {
            return trimmed.to_string();
        }

        // Strip outer function wrapper braces { ... } if present
        let mut s = trimmed;
        if s.starts_with('{') && s.ends_with('}') {
            s = s[1..s.len() - 1].trim();
        }

        match self.rewrite {
            RewriteLevel::Minimal => s.to_string(),
            RewriteLevel::Standard | RewriteLevel::Aggressive => {
                // Strip common strict mode directives at start
                let mut lines: Vec<&str> = s.lines().collect();
                if lines
                    .first()
                    .is_some_and(|l| l.trim() == "\"use strict\";" || l.trim() == "'use strict';")
                {
                    lines.remove(0);
                }
                lines.join("\n").trim().to_string()
            }
        }
    }

    fn detect_and_extract_modules(
        &self,
        source: &str,
        path: &Path,
    ) -> (String, Vec<RawModule>, Vec<String>) {
        let allocator = Allocator::default();
        let source_type = SourceType::from_path(path).unwrap_or_default();
        let parsed = Parser::new(&allocator, source, source_type)
            .with_options(ParseOptions {
                parse_regular_expression: true,
                ..ParseOptions::default()
            })
            .parse();

        let mut warnings = Vec::new();
        if parsed.panicked || !parsed.errors.is_empty() {
            warnings.push(format!(
                "Parser diagnostics: {} errors",
                parsed.errors.len()
            ));
        }

        let mut modules = Vec::new();

        // 1. Check for Webpack Jsonp / WebpackChunk push
        for stmt in &parsed.program.body {
            if let Statement::ExpressionStatement(expr) = stmt
                && let Expression::CallExpression(call) = &expr.expression
            {
                if let Some(extracted) = self.try_extract_webpack_push(call, source) {
                    return ("webpack".to_string(), extracted, warnings);
                }
                if let Some(extracted) = self.try_extract_webpack_iife(call, source) {
                    return ("webpack".to_string(), extracted, warnings);
                }
                if let Some(extracted) = self.try_extract_browserify(call, source) {
                    return ("browserify".to_string(), extracted, warnings);
                }
            }
        }

        // 2. Check for esbuild __commonJS patterns
        let esbuild_modules = self.try_extract_esbuild(&parsed.program, source);
        if !esbuild_modules.is_empty() {
            return ("esbuild".to_string(), esbuild_modules, warnings);
        }

        // 3. Fallback: single module
        modules.push(RawModule {
            id: path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("index.js")
                .to_string(),
            body_span: Span::new(0, source.len() as u32),
        });

        ("unknown".to_string(), modules, warnings)
    }

    fn try_extract_webpack_push(
        &self,
        call: &CallExpression<'_>,
        _source: &str,
    ) -> Option<Vec<RawModule>> {
        let member = call.callee.as_member_expression()?;
        if member.static_property_name() != Some("push") {
            return None;
        }

        let arg = call.arguments.first()?.as_expression()?;
        let arr = match arg {
            Expression::ArrayExpression(arr) => arr,
            _ => return None,
        };

        // Usually [[chunkIds], { moduleId: function(...) { ... } }]
        let modules_arg = arr.elements.get(1)?;
        let modules_obj = match modules_arg {
            ArrayExpressionElement::ObjectExpression(obj) => obj,
            _ => return None,
        };

        let mut raw_modules = Vec::new();
        for prop in &modules_obj.properties {
            if let ObjectPropertyKind::ObjectProperty(p) = prop {
                let key_name = match &p.key {
                    PropertyKey::StringLiteral(s) => s.value.to_string(),
                    PropertyKey::NumericLiteral(n) => n.value.to_string(),
                    PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                    _ => continue,
                };

                let body_span = extract_function_body_from_expr(&p.value)?;

                raw_modules.push(RawModule {
                    id: key_name,
                    body_span,
                });
            }
        }

        if !raw_modules.is_empty() {
            Some(raw_modules)
        } else {
            None
        }
    }

    fn try_extract_webpack_iife(
        &self,
        call: &CallExpression<'_>,
        _source: &str,
    ) -> Option<Vec<RawModule>> {
        // (function(modules) { ... })([function(...) { ... }, ...]) or ({ 0: function(...) { ... } })
        let arg = call.arguments.first()?.as_expression()?;
        let mut raw_modules = Vec::new();

        match arg {
            Expression::ObjectExpression(obj) => {
                for prop in &obj.properties {
                    if let ObjectPropertyKind::ObjectProperty(p) = prop {
                        let key_name = match &p.key {
                            PropertyKey::StringLiteral(s) => s.value.to_string(),
                            PropertyKey::NumericLiteral(n) => n.value.to_string(),
                            PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                            _ => continue,
                        };

                        let body_span = extract_function_body_from_expr(&p.value)?;

                        raw_modules.push(RawModule {
                            id: key_name,
                            body_span,
                        });
                    }
                }
            }
            Expression::ArrayExpression(arr) => {
                for (idx, elem) in arr.elements.iter().enumerate() {
                    if let Some(body_span) = extract_function_body_from_element(elem) {
                        raw_modules.push(RawModule {
                            id: idx.to_string(),
                            body_span,
                        });
                    }
                }
            }
            _ => return None,
        }

        if !raw_modules.is_empty() {
            Some(raw_modules)
        } else {
            None
        }
    }

    fn try_extract_browserify(
        &self,
        call: &CallExpression<'_>,
        _source: &str,
    ) -> Option<Vec<RawModule>> {
        // Browserify: (function(e, t, n) { ... })({ 1: [function(require, module, exports) { ... }, { "./dep": 2 }] }, {}, [1])
        if call.arguments.len() < 3 {
            return None;
        }

        let arg0 = call.arguments.first()?.as_expression()?;
        let obj = match arg0 {
            Expression::ObjectExpression(obj) => obj,
            _ => return None,
        };

        let mut raw_modules = Vec::new();
        for prop in &obj.properties {
            if let ObjectPropertyKind::ObjectProperty(p) = prop {
                let key_name = match &p.key {
                    PropertyKey::StringLiteral(s) => s.value.to_string(),
                    PropertyKey::NumericLiteral(n) => n.value.to_string(),
                    PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                    _ => continue,
                };

                // Browserify value is an array: [function, deps_map]
                if let Expression::ArrayExpression(arr) = &p.value
                    && let Some(first_elem) = arr.elements.first()
                {
                    let body_span = extract_function_body_from_element(first_elem)?;

                    raw_modules.push(RawModule {
                        id: key_name,
                        body_span,
                    });
                }
            }
        }

        if !raw_modules.is_empty() {
            Some(raw_modules)
        } else {
            None
        }
    }

    fn try_extract_esbuild(
        &self,
        program: &oxc_ast::ast::Program<'_>,
        _source: &str,
    ) -> Vec<RawModule> {
        let mut raw_modules = Vec::new();
        for stmt in &program.body {
            if let Some(Declaration::VariableDeclaration(var_decl)) = stmt.as_declaration() {
                for var in &var_decl.declarations {
                    if let Some(init) = &var.init
                        && let Expression::CallExpression(call) = init
                        && let Expression::Identifier(id) = &call.callee
                        && id.name == "__commonJS"
                    {
                        let name = var
                            .id
                            .get_binding_identifiers()
                            .into_iter()
                            .next()
                            .map(|b| b.name.to_string())
                            .unwrap_or_else(|| "commonjs_mod".to_string());

                        if let Some(arg) = call.arguments.first().and_then(|a| a.as_expression()) {
                            let body_span = match arg {
                                Expression::FunctionExpression(f) => {
                                    f.body.as_ref().map(|b| b.span)
                                }
                                Expression::ArrowFunctionExpression(f) => Some(f.body.span),
                                _ => None,
                            };
                            if let Some(span) = body_span {
                                raw_modules.push(RawModule {
                                    id: name,
                                    body_span: span,
                                });
                            }
                        }
                    }
                }
            }
        }
        raw_modules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbundles_webpack_jsonp_push() {
        let bundle_code = r#"
            (self["webpackChunkapp"] = self["webpackChunkapp"] || []).push([
                ["main"],
                {
                    "./src/index.js": function(module, exports, __webpack_require__) {
                        console.log("hello index");
                    },
                    "./src/utils.js": function(module, exports, __webpack_require__) {
                        module.exports = { util: 42 };
                    }
                }
            ]);
        "#;

        let temp_dir = std::env::temp_dir().join("rea_fast_webpack_test");
        let _ = fs::remove_dir_all(&temp_dir);
        let src_file = temp_dir.join("bundle.js");
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(&src_file, bundle_code).unwrap();

        let out_dir = temp_dir.join("out");
        let recoverer = SourceRecoverer::new(ExtractionMode::Structural, RewriteLevel::Minimal);
        let result = recoverer.recover(&src_file, &out_dir).unwrap();

        assert_eq!(result.bundler, "webpack");
        assert_eq!(result.recovered_modules.len(), 2);
        assert!(out_dir.join("src/index.js").exists());
        assert!(out_dir.join("src/utils.js").exists());

        let index_content = fs::read_to_string(out_dir.join("src/index.js")).unwrap();
        assert!(index_content.contains("console.log(\"hello index\");"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn unbundles_browserify() {
        let bundle_code = r#"
            (function(e, t, n) {
                // browserify bootstrap
            })({
                1: [
                    function(require, module, exports) {
                        const a = 1;
                    },
                    { "./dep": 2 }
                ],
                2: [
                    function(require, module, exports) {
                        const b = 2;
                    },
                    {}
                ]
            }, {}, [1]);
        "#;

        let temp_dir = std::env::temp_dir().join("rea_fast_browserify_test");
        let _ = fs::remove_dir_all(&temp_dir);
        let src_file = temp_dir.join("bundle.js");
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(&src_file, bundle_code).unwrap();

        let out_dir = temp_dir.join("out");
        let recoverer = SourceRecoverer::new(ExtractionMode::Structural, RewriteLevel::Minimal);
        let result = recoverer.recover(&src_file, &out_dir).unwrap();

        assert_eq!(result.bundler, "browserify");
        assert_eq!(result.recovered_modules.len(), 2);
        assert!(out_dir.join("modules/1.js").exists());
        assert!(out_dir.join("modules/2.js").exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
