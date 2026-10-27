use oxc_allocator::Allocator;
use oxc_ast::{AstKind, ast::*};
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::{ScopeFlags, SemanticBuilder};
use oxc_span::{GetSpan, SourceType, Span};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::analyze::{Location, Position};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticNodeClass {
    Module,
    Function,
    Parameter,
    Binding,
    Expression,
    Literal,
    PropertySlot,
    CallSite,
    ReturnSite,
    ClosureCapture,
    Promise,
    Task,
    Event,
    Listener,
    Timer,
    ChildProcess,
    Stdio,
    Signal,
    ConfigSource,
    Request,
    Response,
    Boundary,
    Resource,
    UnknownFrontier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticNode {
    pub id: String,
    pub class: SemanticNodeClass,
    pub name: String,
    pub file: String,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SemanticEdge {
    pub source: String,
    pub target: String,
    pub relation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemanticGraph {
    pub nodes: Vec<SemanticNode>,
    pub edges: Vec<SemanticEdge>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TraversalDirection {
    BackwardProvenance,
    ForwardInfluence,
    Callers,
    Ownership,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SemanticSeed {
    pub kind: String,
    pub node_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedTarget {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub classes: Option<Vec<SemanticNodeClass>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SemanticQuery {
    pub seed: SemanticSeed,
    pub direction: TraversalDirection,
    #[serde(default)]
    pub allowed_relations: Option<Vec<String>>,
    #[serde(default)]
    pub expected: Option<ExpectedTarget>,
    #[serde(default)]
    pub include_ambiguous_dynamic_edges: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticTraceResult {
    pub seed: String,
    pub direction: String,
    pub visited_nodes: Vec<SemanticNode>,
    pub visited_edges: Vec<SemanticEdge>,
    pub paths: Vec<Vec<String>>,
    pub reachable_targets: Vec<SemanticNode>,
    pub depth: usize,
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

pub fn build_semantic_graph(source: &str, file_path: &str) -> SemanticGraph {
    let coordinates = Coordinates::new(source);
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        source,
        SourceType::from_path(file_path).unwrap_or_default(),
    )
    .with_options(ParseOptions {
        parse_regular_expression: true,
        ..ParseOptions::default()
    })
    .parse();

    let mut graph = SemanticGraph::default();
    let module_id = format!("mod_{file_path}");
    let module_loc = Location {
        start: Position { line: 1, column: 0 },
        end: coordinates.point(source.len() as u32),
        byte_start: 0,
        byte_end: source.len() as u32,
    };

    graph.nodes.push(SemanticNode {
        id: module_id.clone(),
        class: SemanticNodeClass::Module,
        name: file_path.to_string(),
        file: file_path.to_string(),
        location: module_loc,
        value: None,
    });

    if parsed.panicked {
        return graph;
    }

    let built = SemanticBuilder::new().build(&parsed.program);
    let semantic = &built.semantic;

    // Track symbol_id -> node_id mapping
    let mut symbol_nodes: HashMap<oxc_semantic::SymbolId, String> = HashMap::new();
    // Track function symbol / name -> node_id mapping
    let mut function_nodes: HashMap<String, String> = HashMap::new();
    let mut function_params: HashMap<String, Vec<String>> = HashMap::new();

    // 1. Collect Declarations (Functions, Bindings, Parameters)
    for node in semantic.nodes() {
        match node.kind() {
            AstKind::Function(f) => {
                let span = f.span;
                let name =
                    f.id.as_ref()
                        .map(|id| id.name.to_string())
                        .unwrap_or_else(|| "<anonymous>".into());
                let fn_id = format!("fn_{file_path}_{}_{}", span.start, span.end);

                let fn_node = SemanticNode {
                    id: fn_id.clone(),
                    class: SemanticNodeClass::Function,
                    name: name.clone(),
                    file: file_path.to_string(),
                    location: coordinates.location(span),
                    value: None,
                };
                graph.nodes.push(fn_node);

                if let Some(id) = &f.id {
                    function_nodes.insert(id.name.to_string(), fn_id.clone());
                    if let Some(sym) = id.symbol_id.get() {
                        symbol_nodes.insert(sym, fn_id.clone());
                    }
                }

                // Module or Parent defines Function
                graph.edges.push(SemanticEdge {
                    source: module_id.clone(),
                    target: fn_id.clone(),
                    relation: "defines".into(),
                    location: Some(coordinates.location(span)),
                });

                // Parameters
                let mut params = Vec::new();
                for param in &f.params.items {
                    let p_span = param.span;
                    let p_name = param
                        .pattern
                        .get_binding_identifiers()
                        .into_iter()
                        .next()
                        .map(|i| i.name.to_string())
                        .unwrap_or_else(|| "arg".into());
                    let p_id = format!("param_{file_path}_{}_{}", p_span.start, p_span.end);

                    graph.nodes.push(SemanticNode {
                        id: p_id.clone(),
                        class: SemanticNodeClass::Parameter,
                        name: p_name.clone(),
                        file: file_path.to_string(),
                        location: coordinates.location(p_span),
                        value: None,
                    });

                    graph.edges.push(SemanticEdge {
                        source: fn_id.clone(),
                        target: p_id.clone(),
                        relation: "defines".into(),
                        location: Some(coordinates.location(p_span)),
                    });

                    for ident in param.pattern.get_binding_identifiers() {
                        if let Some(sym) = ident.symbol_id.get() {
                            symbol_nodes.insert(sym, p_id.clone());
                        }
                    }
                    params.push(p_id);
                }
                function_params.insert(fn_id, params);
            }
            AstKind::ArrowFunctionExpression(f) => {
                let span = f.span;
                let fn_id = format!("fn_{file_path}_{}_{}", span.start, span.end);

                graph.nodes.push(SemanticNode {
                    id: fn_id.clone(),
                    class: SemanticNodeClass::Function,
                    name: "<arrow>".into(),
                    file: file_path.to_string(),
                    location: coordinates.location(span),
                    value: None,
                });

                graph.edges.push(SemanticEdge {
                    source: module_id.clone(),
                    target: fn_id.clone(),
                    relation: "defines".into(),
                    location: Some(coordinates.location(span)),
                });

                let mut params = Vec::new();
                for param in &f.params.items {
                    let p_span = param.span;
                    let p_name = param
                        .pattern
                        .get_binding_identifiers()
                        .into_iter()
                        .next()
                        .map(|i| i.name.to_string())
                        .unwrap_or_else(|| "arg".into());
                    let p_id = format!("param_{file_path}_{}_{}", p_span.start, p_span.end);

                    graph.nodes.push(SemanticNode {
                        id: p_id.clone(),
                        class: SemanticNodeClass::Parameter,
                        name: p_name,
                        file: file_path.to_string(),
                        location: coordinates.location(p_span),
                        value: None,
                    });

                    graph.edges.push(SemanticEdge {
                        source: fn_id.clone(),
                        target: p_id.clone(),
                        relation: "defines".into(),
                        location: Some(coordinates.location(p_span)),
                    });

                    for ident in param.pattern.get_binding_identifiers() {
                        if let Some(sym) = ident.symbol_id.get() {
                            symbol_nodes.insert(sym, p_id.clone());
                        }
                    }
                    params.push(p_id);
                }
                function_params.insert(fn_id, params);
            }
            AstKind::VariableDeclarator(v) => {
                for ident in v.id.get_binding_identifiers() {
                    let b_span = ident.span;
                    let b_id = format!("bind_{file_path}_{}_{}", b_span.start, b_span.end);

                    graph.nodes.push(SemanticNode {
                        id: b_id.clone(),
                        class: SemanticNodeClass::Binding,
                        name: ident.name.to_string(),
                        file: file_path.to_string(),
                        location: coordinates.location(b_span),
                        value: None,
                    });

                    graph.edges.push(SemanticEdge {
                        source: module_id.clone(),
                        target: b_id.clone(),
                        relation: "defines".into(),
                        location: Some(coordinates.location(b_span)),
                    });

                    if let Some(sym) = ident.symbol_id.get() {
                        symbol_nodes.insert(sym, b_id.clone());
                    }

                    // Alias detection: const a = b;
                    if let Some(init) = &v.init
                        && let Expression::Identifier(src_id) = init.get_inner_expression()
                        && let Some(ref_id) = src_id.reference_id.get()
                    {
                        let reference = semantic.scoping().get_reference(ref_id);
                        if let Some(target_sym) = reference.symbol_id()
                            && let Some(target_node) = symbol_nodes.get(&target_sym)
                        {
                            graph.edges.push(SemanticEdge {
                                source: b_id.clone(),
                                target: target_node.clone(),
                                relation: "aliases".into(),
                                location: Some(coordinates.location(init.span())),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // 2. Collect Expressions, Calls, Returns, Data-flows
    for node in semantic.nodes() {
        match node.kind() {
            AstKind::CallExpression(call) => {
                let call_span = call.span;
                let call_id = format!("call_{file_path}_{}_{}", call_span.start, call_span.end);
                let callee_text = call.callee.span().source_text(source).to_string();

                graph.nodes.push(SemanticNode {
                    id: call_id.clone(),
                    class: SemanticNodeClass::CallSite,
                    name: callee_text.clone(),
                    file: file_path.to_string(),
                    location: coordinates.location(call_span),
                    value: None,
                });

                // Check direct function call
                if let Expression::Identifier(ident) = call.callee.get_inner_expression() {
                    let name = ident.name.as_str();
                    if let Some(target_fn_id) = function_nodes.get(name) {
                        graph.edges.push(SemanticEdge {
                            source: call_id.clone(),
                            target: target_fn_id.clone(),
                            relation: "calls".into(),
                            location: Some(coordinates.location(call_span)),
                        });

                        // Argument-to-parameter edges
                        if let Some(param_ids) = function_params.get(target_fn_id) {
                            for (idx, arg) in call.arguments.iter().enumerate() {
                                if let Some(param_id) = param_ids.get(idx) {
                                    let arg_span = arg.span();
                                    let arg_id = format!(
                                        "arg_{file_path}_{}_{}",
                                        arg_span.start, arg_span.end
                                    );
                                    let arg_text = arg_span.source_text(source).to_string();

                                    graph.nodes.push(SemanticNode {
                                        id: arg_id.clone(),
                                        class: SemanticNodeClass::Expression,
                                        name: arg_text,
                                        file: file_path.to_string(),
                                        location: coordinates.location(arg_span),
                                        value: None,
                                    });

                                    graph.edges.push(SemanticEdge {
                                        source: arg_id,
                                        target: param_id.clone(),
                                        relation: "argument-to-parameter".into(),
                                        location: Some(coordinates.location(arg_span)),
                                    });
                                }
                            }
                        }
                    }
                }

                // Special handling: IPC channels as boundary nodes
                if (callee_text.starts_with("ipcRenderer.") || callee_text.starts_with("ipcMain."))
                    && let Some(first_arg) = call.arguments.first()
                {
                    let arg_span = first_arg.span();
                    let channel = arg_span
                        .source_text(source)
                        .trim_matches('\'')
                        .trim_matches('"');
                    let boundary_id = format!("ipc_channel_{channel}");

                    graph.nodes.push(SemanticNode {
                        id: boundary_id.clone(),
                        class: SemanticNodeClass::Boundary,
                        name: channel.to_string(),
                        file: file_path.to_string(),
                        location: coordinates.location(arg_span),
                        value: Some(channel.to_string()),
                    });

                    let rel = if callee_text.contains(".send") || callee_text.contains(".invoke") {
                        "constructs-request"
                    } else {
                        "registers-listener"
                    };

                    graph.edges.push(SemanticEdge {
                        source: call_id.clone(),
                        target: boundary_id,
                        relation: rel.into(),
                        location: Some(coordinates.location(call_span)),
                    });
                }
            }
            AstKind::ReturnStatement(ret) => {
                let ret_span = ret.span;
                let ret_id = format!("ret_{file_path}_{}_{}", ret_span.start, ret_span.end);
                graph.nodes.push(SemanticNode {
                    id: ret_id.clone(),
                    class: SemanticNodeClass::ReturnSite,
                    name: "return".into(),
                    file: file_path.to_string(),
                    location: coordinates.location(ret_span),
                    value: None,
                });
            }
            AstKind::AwaitExpression(aw) => {
                let aw_span = aw.span;
                let aw_id = format!("await_{file_path}_{}_{}", aw_span.start, aw_span.end);
                graph.nodes.push(SemanticNode {
                    id: aw_id.clone(),
                    class: SemanticNodeClass::Expression,
                    name: "await".into(),
                    file: file_path.to_string(),
                    location: coordinates.location(aw_span),
                    value: None,
                });
            }
            AstKind::IdentifierReference(ident) => {
                if let Some(ref_id) = ident.reference_id.get() {
                    let reference = semantic.scoping().get_reference(ref_id);
                    if let Some(sym_id) = reference.symbol_id()
                        && let Some(target_id) = symbol_nodes.get(&sym_id)
                    {
                        let span = ident.span;
                        let rel = if reference.is_write() {
                            "writes"
                        } else {
                            "reads"
                        };

                        let ref_node_id = format!("ref_{file_path}_{}_{}", span.start, span.end);
                        graph.edges.push(SemanticEdge {
                            source: ref_node_id,
                            target: target_id.clone(),
                            relation: rel.into(),
                            location: Some(coordinates.location(span)),
                        });

                        // Closure capture: check if symbol scope is outer to current scope
                        let sym_scope = semantic.scoping().symbol_scope_id(sym_id);
                        let cur_scope = node.scope_id();
                        if cur_scope != sym_scope
                            && !semantic
                                .scoping()
                                .scope_flags(sym_scope)
                                .contains(ScopeFlags::Top)
                        {
                            graph.edges.push(SemanticEdge {
                                source: target_id.clone(),
                                target: format!("scope_{cur_scope:?}"),
                                relation: "captures".into(),
                                location: Some(coordinates.location(span)),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    graph.edges.dedup();
    graph
}

impl SemanticGraph {
    pub fn trace(&self, query: &SemanticQuery) -> SemanticTraceResult {
        let node_map: HashMap<&str, &SemanticNode> =
            self.nodes.iter().map(|n| (n.id.as_str(), n)).collect();

        let mut fwd_adj: HashMap<&str, Vec<(usize, &str)>> = HashMap::new();
        let mut bwd_adj: HashMap<&str, Vec<(usize, &str)>> = HashMap::new();

        for (i, edge) in self.edges.iter().enumerate() {
            fwd_adj
                .entry(&edge.source)
                .or_default()
                .push((i, &edge.target));
            bwd_adj
                .entry(&edge.target)
                .or_default()
                .push((i, &edge.source));
        }

        let seed_id = query.seed.node_id.as_str();
        let mut visited_node_ids = HashSet::new();
        let mut visited_edge_indices = HashSet::new();
        let mut queue = VecDeque::new();
        let mut paths: Vec<Vec<String>> = Vec::new();
        let mut parent_map: HashMap<String, (String, usize)> = HashMap::new();

        if node_map.contains_key(seed_id) {
            visited_node_ids.insert(seed_id.to_string());
            queue.push_back((seed_id, 0usize));
        }

        let max_depth = 20;

        while let Some((curr, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            let neighbors = match query.direction {
                TraversalDirection::ForwardInfluence => fwd_adj.get(curr),
                TraversalDirection::BackwardProvenance => bwd_adj.get(curr),
                TraversalDirection::Callers => bwd_adj.get(curr),
                TraversalDirection::Ownership => bwd_adj.get(curr),
            };

            if let Some(edges) = neighbors {
                for &(edge_idx, neighbor) in edges {
                    let edge = &self.edges[edge_idx];

                    let allowed = match query.direction {
                        TraversalDirection::Callers => edge.relation == "calls",
                        TraversalDirection::Ownership => {
                            edge.relation == "defines" || edge.relation == "owns"
                        }
                        _ => {
                            if let Some(allowed_list) = &query.allowed_relations {
                                allowed_list.contains(&edge.relation)
                            } else {
                                true
                            }
                        }
                    };

                    if !allowed {
                        continue;
                    }

                    visited_edge_indices.insert(edge_idx);
                    if visited_node_ids.insert(neighbor.to_string()) {
                        parent_map.insert(neighbor.to_string(), (curr.to_string(), edge_idx));
                        queue.push_back((neighbor, depth + 1));
                    }
                }
            }
        }

        // Reconstruct paths from seed to leaf nodes
        for node_id in &visited_node_ids {
            if node_id != seed_id {
                let mut path = vec![node_id.clone()];
                let mut curr = node_id.as_str();
                while let Some((prev, _)) = parent_map.get(curr) {
                    path.push(prev.clone());
                    if prev == seed_id {
                        break;
                    }
                    curr = prev.as_str();
                }
                path.reverse();
                paths.push(path);
            }
        }

        let visited_nodes: Vec<SemanticNode> = visited_node_ids
            .iter()
            .filter_map(|id| node_map.get(id.as_str()).cloned().cloned())
            .collect();

        let visited_edges: Vec<SemanticEdge> = visited_edge_indices
            .iter()
            .map(|&idx| self.edges[idx].clone())
            .collect();

        let reachable_targets: Vec<SemanticNode> = visited_nodes
            .iter()
            .filter(|n| {
                if let Some(expected) = &query.expected
                    && let Some(classes) = &expected.classes
                {
                    return classes.contains(&n.class);
                }
                true
            })
            .cloned()
            .collect();

        let depth = paths.iter().map(|p| p.len()).max().unwrap_or(0);

        SemanticTraceResult {
            seed: query.seed.node_id.clone(),
            direction: format!("{:?}", query.direction).to_lowercase(),
            visited_nodes,
            visited_edges,
            paths,
            reachable_targets,
            depth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_semantics_and_traces_call_path() {
        let code = r#"
            function processInput(x) {
                return x * 2;
            }

            function main() {
                const a = 10;
                const b = a;
                const res = processInput(b);
            }
        "#;

        let graph = build_semantic_graph(code, "test.js");

        assert!(graph.nodes.iter().any(|n| n.name == "processInput"));
        assert!(graph.nodes.iter().any(|n| n.name == "main"));
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.relation == "argument-to-parameter")
        );
        assert!(graph.edges.iter().any(|e| e.relation == "aliases"));

        let process_fn = graph
            .nodes
            .iter()
            .find(|n| n.name == "processInput")
            .unwrap();

        let query = SemanticQuery {
            seed: SemanticSeed {
                kind: "semantic-node".into(),
                node_id: process_fn.id.clone(),
            },
            direction: TraversalDirection::Callers,
            allowed_relations: None,
            expected: None,
            include_ambiguous_dynamic_edges: None,
        };

        let trace = graph.trace(&query);
        assert!(!trace.visited_nodes.is_empty());
    }

    #[test]
    fn detects_ipc_boundaries() {
        let code = r#"
            const { ipcRenderer } = require('electron');
            ipcRenderer.send('user:login', { user: 'admin' });
        "#;

        let graph = build_semantic_graph(code, "renderer.js");
        let boundary = graph
            .nodes
            .iter()
            .find(|n| n.class == SemanticNodeClass::Boundary);
        assert!(boundary.is_some());
        assert_eq!(boundary.unwrap().name, "user:login");
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.relation == "constructs-request")
        );
    }
}
