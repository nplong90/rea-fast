use oxc_allocator::Allocator;
use oxc_ast::{
    ast::*,
    AstKind,
};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::SemanticBuilder;
use oxc_span::{GetSpan, SourceType, Span};
use serde::Serialize;

use crate::analyze::{Location, Position};

#[derive(Debug, Clone, Serialize)]
pub struct IpcFinding {
    pub channel: Option<String>,
    pub process: &'static str,
    pub operation: &'static str,
    pub handler_kind: &'static str,
    pub location: Location,
}

#[derive(Debug, Clone, Serialize)]
pub struct SenderValidationFinding {
    pub subject: String,
    pub operator: String,
    pub location: Location,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WebPreferencesFinding {
    pub node_integration: Option<bool>,
    pub context_isolation: Option<bool>,
    pub sandbox: Option<bool>,
    pub web_security: Option<bool>,
    pub preload: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserWindowFinding {
    pub web_preferences: WebPreferencesFinding,
    pub location: Location,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContextBridgeFinding {
    pub api_name: String,
    pub exposed_methods: Vec<String>,
    pub location: Location,
}

#[derive(Debug, Clone, Serialize)]
pub struct UtilityProcessFinding {
    pub module_path: Option<String>,
    pub service_name: Option<String>,
    pub location: Location,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ElectronStaticFindings {
    pub ipc: Vec<IpcFinding>,
    pub sender_validations: Vec<SenderValidationFinding>,
    pub browser_windows: Vec<BrowserWindowFinding>,
    pub context_bridge_apis: Vec<ContextBridgeFinding>,
    pub utility_processes: Vec<UtilityProcessFinding>,
}

struct Coordinates<'s> {
    source: &'s str,
    starts: Vec<usize>,
}

impl<'s> Coordinates<'s> {
    fn new(source: &'s str) -> Self {
        let mut starts = vec![0];
        let mut chars = source.char_indices().peekable();
        while let Some((offset, ch)) = chars.next() {
            if ch == '\r' && chars.peek().is_some_and(|(_, c)| *c == '\n') {
                continue;
            }
            if matches!(ch, '\r' | '\n' | '\u{2028}' | '\u{2029}') {
                starts.push(offset + ch.len_utf8());
            }
        }
        Self { source, starts }
    }

    fn point(&self, byte: u32) -> Position {
        let byte = byte as usize;
        let index = self.starts.partition_point(|&start| start <= byte) - 1;
        Position {
            line: index as u32 + 1,
            column: self.source[self.starts[index]..byte].encode_utf16().count() as u32,
        }
    }

    fn location(&self, span: Span) -> Location {
        Location {
            start: self.point(span.start),
            end: self.point(span.end),
            byte_start: span.start,
            byte_end: span.end,
        }
    }
}

fn string_literal(expr: &Expression<'_>) -> Option<String> {
    match expr.get_inner_expression() {
        Expression::StringLiteral(s) => Some(s.value.to_string()),
        Expression::TemplateLiteral(t) if t.is_no_substitution_template() => {
            t.quasi().map(|s| s.to_string())
        }
        _ => None,
    }
}

fn boolean_literal(expr: &Expression<'_>) -> Option<bool> {
    match expr.get_inner_expression() {
        Expression::BooleanLiteral(b) => Some(b.value),
        _ => None,
    }
}

fn expr_text(expr: &Expression<'_>, source: &str) -> String {
    expr.span().source_text(source).to_string()
}

fn callee_chain<'a>(expr: &'a Expression<'_>) -> Vec<&'a str> {
    let mut chain = Vec::new();
    let mut cur = expr.get_inner_expression();
    loop {
        match cur {
            Expression::Identifier(id) => {
                chain.push(id.name.as_str());
                break;
            }
            Expression::ComputedMemberExpression(m) => {
                cur = m.object.get_inner_expression();
            }
            Expression::StaticMemberExpression(m) => {
                chain.push(m.property.name.as_str());
                cur = m.object.get_inner_expression();
            }
            Expression::PrivateFieldExpression(m) => {
                chain.push(m.field.name.as_str());
                cur = m.object.get_inner_expression();
            }
            Expression::CallExpression(c) => {
                cur = c.callee.get_inner_expression();
            }
            _ => break,
        }
    }
    chain.reverse();
    chain
}

fn classify_handler(arg: Option<&Argument<'_>>) -> &'static str {
    match arg.and_then(|a| a.as_expression()).map(|e| e.get_inner_expression()) {
        None => "missing",
        Some(Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)) => "inline-function",
        Some(Expression::Identifier(_)) => "identifier",
        Some(Expression::StaticMemberExpression(_) | Expression::ComputedMemberExpression(_)) => "member-expression",
        _ => "dynamic-expression",
    }
}

pub fn analyze_electron_source(source: &str, path: &str) -> ElectronStaticFindings {
    let coordinates = Coordinates::new(source);
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::from_path(path).unwrap_or_default())
        .with_options(ParseOptions {
            parse_regular_expression: true,
            ..ParseOptions::default()
        })
        .parse();

    let mut findings = ElectronStaticFindings::default();
    if parsed.panicked {
        return findings;
    }

    let built = SemanticBuilder::new().build(&parsed.program);
    let semantic = &built.semantic;

    for node in semantic.nodes() {
        match node.kind() {
            AstKind::CallExpression(call) => {
                let callee = &call.callee;
                let chain = callee_chain(callee);

                // IPC detection
                if let Some(target) = chain.first().copied() {
                    let is_ipc_main = target == "ipcMain" || chain.iter().any(|&s| s == "ipcMain");
                    let is_ipc_renderer = target == "ipcRenderer" || chain.iter().any(|&s| s == "ipcRenderer");
                    let is_web_contents = target == "webContents" || chain.iter().any(|&s| s == "webContents");

                    if is_ipc_main || is_ipc_renderer || is_web_contents {
                        let method = chain.last().copied().unwrap_or("");
                        let (process, op) = match method {
                            "send" if is_ipc_renderer => ("renderer", "send"),
                            "sendSync" if is_ipc_renderer => ("renderer", "send-sync"),
                            "invoke" if is_ipc_renderer => ("renderer", "invoke"),
                            "postMessage" if is_ipc_renderer => ("renderer", "post-message"),
                            "sendToHost" if is_ipc_renderer => ("renderer", "send-to-host"),
                            "on" if is_ipc_renderer => ("renderer", "on"),
                            "once" if is_ipc_renderer => ("renderer", "once"),
                            "handle" if is_ipc_main => ("main", "handle"),
                            "handleOnce" if is_ipc_main => ("main", "handle-once"),
                            "on" if is_ipc_main => ("main", "on"),
                            "once" if is_ipc_main => ("main", "once"),
                            "send" if is_web_contents => ("main", "send"),
                            "postMessage" if is_web_contents => ("main", "post-message"),
                            _ => ("", ""),
                        };

                        if !process.is_empty() {
                            let channel = call.arguments.first().and_then(|a| a.as_expression()).and_then(string_literal);
                            let handler_kind = classify_handler(call.arguments.get(1));
                            findings.ipc.push(IpcFinding {
                                channel,
                                process,
                                operation: op,
                                handler_kind,
                                location: coordinates.location(call.span),
                            });
                        }
                    }
                }

                // contextBridge.exposeInMainWorld / exposeInIsolatedWorld
                if chain.contains(&"contextBridge") {
                    let method = chain.last().copied().unwrap_or("");
                    if method == "exposeInMainWorld" || method == "exposeInIsolatedWorld" {
                        let api_name = call
                            .arguments
                            .first()
                            .and_then(|a| a.as_expression())
                            .and_then(string_literal)
                            .unwrap_or_else(|| "<dynamic>".into());

                        let mut exposed_methods = Vec::new();
                        if let Some(arg2) = call.arguments.get(1).and_then(|a| a.as_expression()) {
                            if let Expression::ObjectExpression(obj) = arg2.get_inner_expression() {
                                for prop in &obj.properties {
                                    if let ObjectPropertyKind::ObjectProperty(p) = prop {
                                        if let Some(name) = p.key.static_name() {
                                            exposed_methods.push(name.to_string());
                                        }
                                    }
                                }
                            }
                        }

                        findings.context_bridge_apis.push(ContextBridgeFinding {
                            api_name,
                            exposed_methods,
                            location: coordinates.location(call.span),
                        });
                    }
                }

                // utilityProcess.fork(modulePath, args, options)
                if chain.contains(&"utilityProcess") && chain.last().copied() == Some("fork") {
                    let module_path = call
                        .arguments
                        .first()
                        .and_then(|a| a.as_expression())
                        .and_then(string_literal);

                    let mut service_name = None;
                    if let Some(arg3) = call.arguments.get(2).and_then(|a| a.as_expression()) {
                        if let Expression::ObjectExpression(opts) = arg3.get_inner_expression() {
                            for prop in &opts.properties {
                                if let ObjectPropertyKind::ObjectProperty(p) = prop {
                                    if p.key.static_name().as_deref() == Some("serviceName") {
                                        service_name = string_literal(&p.value);
                                    }
                                }
                            }
                        }
                    }

                    findings.utility_processes.push(UtilityProcessFinding {
                        module_path,
                        service_name,
                        location: coordinates.location(call.span),
                    });
                }

                // Sender validation call: e.g. senderFrame.url.startsWith(...), event.sender.getURL()
                if let Expression::StaticMemberExpression(m) = callee.get_inner_expression() {
                    let method = m.property.name.as_str();
                    if matches!(method, "startsWith" | "endsWith" | "includes") {
                        let subj = expr_text(&m.object, source);
                        if is_sender_subject(&subj) {
                            findings.sender_validations.push(SenderValidationFinding {
                                subject: subj,
                                operator: method.to_string(),
                                location: coordinates.location(call.span),
                            });
                        }
                    }
                }
            }

            // new BrowserWindow({ webPreferences: { ... } })
            AstKind::NewExpression(new_expr) => {
                let callee = &new_expr.callee;
                let chain = callee_chain(callee);
                if chain.last().copied() == Some("BrowserWindow") {
                    let mut prefs = WebPreferencesFinding::default();
                    if let Some(arg) = new_expr.arguments.first().and_then(|a| a.as_expression()) {
                        if let Expression::ObjectExpression(opts) = arg.get_inner_expression() {
                            for prop in &opts.properties {
                                if let ObjectPropertyKind::ObjectProperty(p) = prop {
                                    if p.key.static_name().as_deref() == Some("webPreferences") {
                                        if let Expression::ObjectExpression(wp) = p.value.get_inner_expression() {
                                            for wp_prop in &wp.properties {
                                                if let ObjectPropertyKind::ObjectProperty(wpp) = wp_prop {
                                                    match wpp.key.static_name().as_deref() {
                                                        Some("nodeIntegration") => {
                                                            prefs.node_integration = boolean_literal(&wpp.value);
                                                        }
                                                        Some("contextIsolation") => {
                                                            prefs.context_isolation = boolean_literal(&wpp.value);
                                                        }
                                                        Some("sandbox") => {
                                                            prefs.sandbox = boolean_literal(&wpp.value);
                                                        }
                                                        Some("webSecurity") => {
                                                            prefs.web_security = boolean_literal(&wpp.value);
                                                        }
                                                        Some("preload") => {
                                                            prefs.preload = string_literal(&wpp.value);
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    findings.browser_windows.push(BrowserWindowFinding {
                        web_preferences: prefs,
                        location: coordinates.location(new_expr.span),
                    });
                }
            }

            // Sender validation comparisons: ==, ===, !=, !==
            AstKind::BinaryExpression(bin) => {
                let op = bin.operator.as_str();
                if matches!(op, "==" | "===" | "!=" | "!==" | "in") {
                    let left = expr_text(&bin.left, source);
                    let right = expr_text(&bin.right, source);
                    if is_sender_subject(&left) {
                        findings.sender_validations.push(SenderValidationFinding {
                            subject: left,
                            operator: op.to_string(),
                            location: coordinates.location(bin.span),
                        });
                    } else if is_sender_subject(&right) {
                        findings.sender_validations.push(SenderValidationFinding {
                            subject: right,
                            operator: op.to_string(),
                            location: coordinates.location(bin.span),
                        });
                    }
                }
            }

            _ => {}
        }
    }

    findings
}

fn is_sender_subject(text: &str) -> bool {
    let patterns = [
        "senderFrame.origin",
        "senderFrame.url",
        "senderFrame",
        "sender.getURL()",
        "sender.getURL",
        "sender.id",
        "sender.origin",
        "event.sender",
        "e.sender",
        "frameId",
        "processId",
    ];
    patterns.iter().any(|&p| text.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ipc_and_validations() {
        let code = r#"
            const { ipcMain, ipcRenderer, contextBridge, BrowserWindow, utilityProcess } = require('electron');

            ipcMain.handle('get-data', (event, arg) => {
                if (event.senderFrame.origin === 'https://trusted.com') {
                    return 42;
                }
                return null;
            });

            ipcRenderer.send('async-ping', 'ping');

            contextBridge.exposeInMainWorld('myAPI', {
                getData: () => ipcRenderer.invoke('get-data'),
                ping: () => ipcRenderer.send('async-ping'),
            });

            const win = new BrowserWindow({
                webPreferences: {
                    nodeIntegration: false,
                    contextIsolation: true,
                    sandbox: true,
                    preload: '/path/to/preload.js'
                }
            });

            utilityProcess.fork('./worker.js', [], { serviceName: 'worker-service' });
        "#;

        let findings = analyze_electron_source(code, "test.js");

        assert_eq!(findings.ipc.len(), 4);
        assert_eq!(findings.ipc[0].channel.as_deref(), Some("get-data"));
        assert_eq!(findings.ipc[0].process, "main");
        assert_eq!(findings.ipc[0].operation, "handle");
        assert_eq!(findings.ipc[0].handler_kind, "inline-function");

        assert_eq!(findings.ipc[1].channel.as_deref(), Some("async-ping"));
        assert_eq!(findings.ipc[1].process, "renderer");
        assert_eq!(findings.ipc[1].operation, "send");

        assert_eq!(findings.ipc[2].channel.as_deref(), Some("get-data"));
        assert_eq!(findings.ipc[2].process, "renderer");
        assert_eq!(findings.ipc[2].operation, "invoke");

        assert_eq!(findings.ipc[3].channel.as_deref(), Some("async-ping"));
        assert_eq!(findings.ipc[3].process, "renderer");
        assert_eq!(findings.ipc[3].operation, "send");

        assert_eq!(findings.sender_validations.len(), 1);
        assert!(findings.sender_validations[0].subject.contains("senderFrame.origin"));
        assert_eq!(findings.sender_validations[0].operator, "===");

        assert_eq!(findings.context_bridge_apis.len(), 1);
        assert_eq!(findings.context_bridge_apis[0].api_name, "myAPI");
        assert_eq!(findings.context_bridge_apis[0].exposed_methods, vec!["getData", "ping"]);

        assert_eq!(findings.browser_windows.len(), 1);
        let wp = &findings.browser_windows[0].web_preferences;
        assert_eq!(wp.node_integration, Some(false));
        assert_eq!(wp.context_isolation, Some(true));
        assert_eq!(wp.sandbox, Some(true));
        assert_eq!(wp.preload.as_deref(), Some("/path/to/preload.js"));

        assert_eq!(findings.utility_processes.len(), 1);
        assert_eq!(findings.utility_processes[0].module_path.as_deref(), Some("./worker.js"));
        assert_eq!(findings.utility_processes[0].service_name.as_deref(), Some("worker-service"));
    }
}
