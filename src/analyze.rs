use oxc_allocator::Allocator;
use oxc_ast::{AstKind, ast::*};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::{Semantic, SemanticBuilder};
use oxc_span::{GetSpan, SourceType, Span};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

#[derive(Default, Serialize)]
pub struct FileAnalysis {
    pub path: String,
    pub sha256: Option<String>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub functions: Vec<FunctionInfo>,
    pub classes: Vec<ClassInfo>,
    pub lines: usize,
    pub bytes: usize,
    pub symbols: usize,
    pub parse_errors: usize,
    pub diagnostics: Vec<String>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct Position { pub line: u32, pub column: u32 }
#[derive(Serialize)]
pub struct Location { pub start: Position, pub end: Position, pub byte_start: u32, pub byte_end: u32 }
#[derive(Serialize)]
pub struct ImportSpecifier { pub imported: String, pub local: String, pub kind: &'static str, pub type_only: bool }
#[derive(Serialize)]
pub struct ImportInfo {
    pub source: Option<String>, pub kind: &'static str, pub type_only: bool,
    pub specifiers: Vec<ImportSpecifier>, pub location: Location,
}
#[derive(Serialize)]
pub struct ExportInfo {
    pub name: String, pub local: Option<String>, pub source: Option<String>,
    pub kind: &'static str, pub type_only: bool, pub location: Location,
}
#[derive(Serialize)]
pub struct FunctionInfo {
    pub name: String, pub params: usize, pub is_async: bool, pub is_generator: bool,
    pub type_only: bool, pub location: Location,
}
#[derive(Serialize)]
pub struct MemberInfo { pub name: String, pub is_static: bool, pub kind: &'static str, pub location: Location }
#[derive(Serialize)]
pub struct ClassInfo { pub name: String, pub methods: Vec<MemberInfo>, pub properties: Vec<MemberInfo>, pub location: Location }

pub fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

struct Coordinates<'s> { source: &'s str, starts: Vec<usize> }
impl<'s> Coordinates<'s> {
    fn new(source: &'s str) -> Self {
        let mut starts = vec![0];
        let mut chars = source.char_indices().peekable();
        while let Some((offset, ch)) = chars.next() {
            if ch == '\r' && chars.peek().is_some_and(|(_, c)| *c == '\n') { continue; }
            if matches!(ch, '\r' | '\n' | '\u{2028}' | '\u{2029}') { starts.push(offset + ch.len_utf8()); }
        }
        Self { source, starts }
    }
    fn point(&self, byte: u32) -> Position {
        let byte = byte as usize;
        let index = self.starts.partition_point(|&start| start <= byte) - 1;
        Position { line: index as u32 + 1, column: self.source[self.starts[index]..byte].encode_utf16().count() as u32 }
    }
    fn location(&self, span: Span) -> Location {
        Location { start: self.point(span.start), end: self.point(span.end), byte_start: span.start, byte_end: span.end }
    }
}

pub fn analyze_file(path: &Path, root: &Path, limit: u64) -> FileAnalysis {
    let relative = path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/");
    let read = || -> Result<String, Box<dyn std::error::Error>> {
        let file = std::fs::File::open(path)?;
        if file.metadata()?.len() > limit { return Err(format!("File exceeds --max-file-bytes={limit}").into()); }
        let mut source = String::new();
        file.take(limit + 1).read_to_string(&mut source)?;
        if source.len() as u64 > limit { return Err(format!("File exceeds --max-file-bytes={limit}").into()); }
        Ok(source)
    };
    match read() {
        Ok(source) => analyze_source(&source, &relative),
        Err(error) => FileAnalysis { path: relative, error: Some(error.to_string()), ..FileAnalysis::default() },
    }
}

fn binding_name(pattern: &BindingPattern<'_>) -> Option<String> {
    if let BindingPatternKind::BindingIdentifier(id) = &pattern.kind { Some(id.name.to_string()) } else { None }
}
fn property_name(key: &PropertyKey<'_>, source: &str) -> String {
    if let PropertyKey::PrivateIdentifier(id) = key { return format!("#{}", id.name); }
    key.static_name().map(|s| s.into_owned()).unwrap_or_else(|| format!("[{}]", key.span().source_text(source)))
}
fn literal(expression: &Expression<'_>) -> Option<String> {
    match expression.get_inner_expression() {
        Expression::StringLiteral(s) => Some(s.value.to_string()),
        Expression::TemplateLiteral(t) if t.is_no_substitution_template() => t.quasi().map(|s| s.to_string()),
        _ => None,
    }
}
fn ambient(expression: &Expression<'_>, name: &str, semantic: &Semantic<'_>) -> bool {
    matches!(expression.get_inner_expression(), Expression::Identifier(id) if id.name == name && id.reference_id.get().is_some_and(|reference| semantic.scoping().get_reference(reference).symbol_id().is_none()))
}
fn commonjs_object(expression: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    if ambient(expression, "exports", semantic) { return true; }
    expression.get_inner_expression().as_member_expression().is_some_and(|member| member.static_property_name() == Some("exports") && ambient(member.object(), "module", semantic))
}
fn assigned_name(parent: Option<AstKind<'_>>, source: &str) -> Option<String> {
    match parent {
        Some(AstKind::VariableDeclarator(v)) => binding_name(&v.id),
        Some(AstKind::MethodDefinition(m)) => Some(property_name(&m.key, source)),
        Some(AstKind::PropertyDefinition(p)) => Some(property_name(&p.key, source)),
        Some(AstKind::ObjectProperty(p)) => Some(property_name(&p.key, source)),
        Some(AstKind::AssignmentExpression(a)) => Some(a.left.span().source_text(source).to_owned()),
        Some(AstKind::ExportDefaultDeclaration(_)) => Some("default".into()),
        _ => None,
    }
}

pub fn analyze_source(source: &str, path: &str) -> FileAnalysis {
    let coordinates = Coordinates::new(source);
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::from_path(path).unwrap_or_default())
        .with_options(ParseOptions { parse_regular_expression: true, ..ParseOptions::default() }).parse();
    let mut result = FileAnalysis {
        path: path.into(), sha256: Some(digest(source.as_bytes())), bytes: source.len(),
        lines: if source.is_empty() { 0 } else { coordinates.starts.len() - usize::from(coordinates.starts.last() == Some(&source.len())) },
        parse_errors: parsed.errors.len(), diagnostics: parsed.errors.iter().map(ToString::to_string).collect(),
        ..FileAnalysis::default()
    };
    if parsed.panicked { return result; }
    let built = SemanticBuilder::new().build(&parsed.program);
    let semantic = &built.semantic;
    result.parse_errors += built.errors.len();
    result.diagnostics.extend(built.errors.iter().map(ToString::to_string));
    for node in semantic.nodes() {
        let parent = semantic.nodes().parent_kind(node.id());
        match node.kind() {
            AstKind::BindingIdentifier(_) => result.symbols += 1,
            AstKind::ImportDeclaration(import) => {
                let type_only = import.import_kind.is_type();
                let specifiers = import.specifiers.iter().flatten().map(|s| match s {
                    ImportDeclarationSpecifier::ImportSpecifier(s) => ImportSpecifier { imported: s.imported.name().to_string(), local: s.local.name.to_string(), kind: "named", type_only: type_only || s.import_kind.is_type() },
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => ImportSpecifier { imported: "default".into(), local: s.local.name.to_string(), kind: "default", type_only },
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => ImportSpecifier { imported: "*".into(), local: s.local.name.to_string(), kind: "namespace", type_only },
                }).collect();
                result.imports.push(ImportInfo { source: Some(import.source.value.to_string()), kind: "static-import", type_only, specifiers, location: coordinates.location(import.span) });
            }
            AstKind::ImportExpression(import) => result.imports.push(ImportInfo { source: literal(&import.source), kind: "dynamic-import", type_only: false, specifiers: vec![], location: coordinates.location(import.span) }),
            AstKind::TSImportEqualsDeclaration(import) => {
                if let TSModuleReference::ExternalModuleReference(reference) = &import.module_reference {
                    result.imports.push(ImportInfo { source: Some(reference.expression.value.to_string()), kind: "require", type_only: import.import_kind.is_type(), specifiers: vec![ImportSpecifier { imported: "*".into(), local: import.id.name.to_string(), kind: "namespace", type_only: import.import_kind.is_type() }], location: coordinates.location(import.span) });
                }
            }
            AstKind::CallExpression(call) if ambient(&call.callee, "require", semantic) && !call.optional => {
                let source = call.arguments.first().and_then(|a| a.as_expression()).and_then(literal);
                let specifiers = if let Some(AstKind::VariableDeclarator(v)) = parent {
                    v.id.get_binding_identifiers().iter().map(|id| ImportSpecifier { imported: "*".into(), local: id.name.to_string(), kind: "commonjs-binding", type_only: false }).collect()
                } else { vec![] };
                result.imports.push(ImportInfo { source, kind: "require", type_only: false, specifiers, location: coordinates.location(call.span) });
            }
            AstKind::ExportNamedDeclaration(export) => {
                let export_source = export.source.as_ref().map(|s| s.value.to_string());
                for specifier in &export.specifiers {
                    result.exports.push(ExportInfo { name: specifier.exported.name().to_string(), local: Some(specifier.local.name().to_string()), source: export_source.clone(), kind: if export_source.is_some() { "re-export" } else { "named" }, type_only: export.export_kind.is_type() || specifier.export_kind.is_type(), location: coordinates.location(specifier.span) });
                }
                if let Some(declaration) = &export.declaration {
                    let type_only = export.export_kind.is_type() || matches!(declaration, Declaration::TSTypeAliasDeclaration(_) | Declaration::TSInterfaceDeclaration(_));
                    let names: Vec<String> = match declaration {
                        Declaration::VariableDeclaration(v) => v.declarations.iter().flat_map(|d| d.id.get_binding_identifiers().into_iter().map(|id| id.name.to_string())).collect(),
                        Declaration::FunctionDeclaration(f) => f.id.iter().map(|id| id.name.to_string()).collect(),
                        Declaration::ClassDeclaration(c) => c.id.iter().map(|id| id.name.to_string()).collect(),
                        Declaration::TSTypeAliasDeclaration(t) => vec![t.id.name.to_string()],
                        Declaration::TSInterfaceDeclaration(t) => vec![t.id.name.to_string()],
                        Declaration::TSEnumDeclaration(t) => vec![t.id.name.to_string()],
                        Declaration::TSModuleDeclaration(t) => vec![t.id.span().source_text(source).into()],
                        _ => vec![],
                    };
                    for name in names { result.exports.push(ExportInfo { local: Some(name.clone()), name, source: None, kind: "named", type_only, location: coordinates.location(declaration.span()) }); }
                }
            }
            AstKind::ExportDefaultDeclaration(export) => result.exports.push(ExportInfo { name: "default".into(), local: assigned_name(Some(AstKind::ExportDefaultDeclaration(export)), source), source: None, kind: "default", type_only: matches!(export.declaration, ExportDefaultDeclarationKind::TSInterfaceDeclaration(_)), location: coordinates.location(export.span) }),
            AstKind::ExportAllDeclaration(export) => result.exports.push(ExportInfo { name: export.exported.as_ref().map(|n| n.name().to_string()).unwrap_or_else(|| "*".into()), local: Some("*".into()), source: Some(export.source.value.to_string()), kind: "re-export", type_only: export.export_kind.is_type(), location: coordinates.location(export.span) }),
            AstKind::TSExportAssignment(export) => result.exports.push(ExportInfo { name: "default".into(), local: None, source: None, kind: "commonjs", type_only: false, location: coordinates.location(export.span) }),
            AstKind::AssignmentExpression(assignment) => {
                if let Some(member) = assignment.left.as_member_expression() {
                    let name = if commonjs_object(member.object(), semantic) { member.static_property_name().map(str::to_owned) }
                        else if member.static_property_name() == Some("exports") && ambient(member.object(), "module", semantic) { Some("default".into()) } else { None };
                    if let Some(name) = name {
                        result.exports.push(ExportInfo { name, local: None, source: None, kind: "commonjs", type_only: false, location: coordinates.location(assignment.span) });
                    }
                }
            }
            AstKind::Function(function) => result.functions.push(FunctionInfo { name: assigned_name(parent, source).or_else(|| function.id.as_ref().map(|id| id.name.to_string())).unwrap_or_else(|| "<anonymous>".into()), params: function.params.items.len() + usize::from(function.params.rest.is_some()), is_async: function.r#async, is_generator: function.generator, type_only: function.body.is_none(), location: coordinates.location(function.span) }),
            AstKind::ArrowFunctionExpression(function) => result.functions.push(FunctionInfo { name: assigned_name(parent, source).unwrap_or_else(|| "<anonymous>".into()), params: function.params.items.len() + usize::from(function.params.rest.is_some()), is_async: function.r#async, is_generator: false, type_only: false, location: coordinates.location(function.span) }),
            AstKind::Class(class) => {
                let mut methods = vec![];
                let mut properties = vec![];
                for member in &class.body.body {
                    match member {
                        ClassElement::MethodDefinition(m) => methods.push(MemberInfo { name: property_name(&m.key, source), is_static: m.r#static, kind: match m.kind { MethodDefinitionKind::Get => "get", MethodDefinitionKind::Set => "set", MethodDefinitionKind::Constructor => "constructor", _ => "method" }, location: coordinates.location(m.span) }),
                        ClassElement::PropertyDefinition(p) => properties.push(MemberInfo { name: property_name(&p.key, source), is_static: p.r#static, kind: "property", location: coordinates.location(p.span) }),
                        ClassElement::AccessorProperty(p) => properties.push(MemberInfo { name: property_name(&p.key, source), is_static: p.r#static, kind: "accessor", location: coordinates.location(p.span) }),
                        _ => {}
                    }
                }
                result.classes.push(ClassInfo { name: assigned_name(parent, source).or_else(|| class.id.as_ref().map(|id| id.name.to_string())).unwrap_or_else(|| "<anonymous>".into()), methods, properties, location: coordinates.location(class.span) });
            }
            _ => {}
        }
    }
    result
}
