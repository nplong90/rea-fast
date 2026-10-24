use crate::analyze::{FileAnalysis, Location, digest};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io::{self, Write}, path::{Component, Path, PathBuf}};

#[derive(Serialize)]
pub struct Dependency<'a> {
    pub source: Option<&'a str>,
    pub target: Option<&'a str>,
    pub kind: &'static str,
    pub type_only: bool,
    pub resolution: &'static str,
    pub location: &'a Location,
    #[serde(skip)]
    target_index: Option<usize>,
}

fn normalize(path: &Path) -> Option<PathBuf> {
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(s) => result.push(s),
            Component::CurDir => {},
            Component::ParentDir => if !result.pop() { return None; },
            _ => return None,
        }
    }
    Some(result)
}

fn resolve(file: &str, source: &str, index: &HashMap<&str, usize>) -> Option<usize> {
    if !source.starts_with("./") && !source.starts_with("../") { return None; }
    let base = normalize(&Path::new(file).parent()?.join(source))?;
    let lookup = |path: &Path| index.get(path.to_str()?).copied();
    // ponytail: relative source files only; add a package/tsconfig resolver when alias resolution is required.
    match base.extension().and_then(|s| s.to_str()) {
        Some("js") => for ext in ["ts", "tsx", "d.ts"] { if let Some(i) = lookup(&base.with_extension(ext)) { return Some(i); } },
        Some("jsx") => if let Some(i) = lookup(&base.with_extension("tsx")) { return Some(i); },
        Some("mjs") => for ext in ["mts", "d.mts"] { if let Some(i) = lookup(&base.with_extension(ext)) { return Some(i); } },
        Some("cjs") => for ext in ["cts", "d.cts"] { if let Some(i) = lookup(&base.with_extension(ext)) { return Some(i); } },
        _ => {}
    }
    if let Some(i) = lookup(&base) { return Some(i); }
    if base.extension().is_none() {
        for ext in ["ts", "tsx", "js", "jsx", "mts", "cts", "mjs", "cjs"] {
            let candidate = PathBuf::from(format!("{}.{}", base.display(), ext));
            if let Some(i) = lookup(&candidate) { return Some(i); }
        }
        for ext in ["ts", "tsx", "js", "jsx", "mts", "cts", "mjs", "cjs"] {
            if let Some(i) = lookup(&base.join(format!("index.{ext}"))) { return Some(i); }
        }
    }
    None
}

pub fn dependencies(files: &[FileAnalysis]) -> Vec<Vec<Dependency<'_>>> {
    let index: HashMap<_, _> = files.iter().enumerate().map(|(i, f)| (f.path.as_str(), i)).collect();
    files.iter().map(|file| {
        let imports = file.imports.iter().map(|i| (i.source.as_deref(), i.kind, i.type_only, &i.location));
        let exports = file.exports.iter().filter(|e| e.source.is_some()).map(|e| (e.source.as_deref(), "re-export", e.type_only, &e.location));
        imports.chain(exports).map(|(source, kind, type_only, location)| {
            let target_index = source.and_then(|s| resolve(&file.path, s, &index));
            let resolution = if target_index.is_some() { "relative-source-inference" }
                else if source.is_none() { "dynamic-unknown" }
                else if source.is_some_and(|s| s.starts_with("./") || s.starts_with("../")) { "unresolved-relative" }
                else { "external-or-alias" };
            Dependency { source, target: target_index.map(|i| files[i].path.as_str()), kind, type_only, resolution, location, target_index }
        }).collect()
    }).collect()
}

fn coverage(status: &str, limit: u64) -> Value {
    json!({"status":status,"truncated":false,"omitted_count":if status == "complete" { Some(0) } else { None },"limits":[{"name":"max-file-bytes","value":limit,"unit":"bytes"}]})
}
fn semantic_id(prefix: &str, value: &Value) -> String {
    format!("{prefix}_{}", digest(&serde_json::to_vec(value).expect("JSON values serialize")))
}
fn evidence(file: &FileAnalysis, location: Option<&Location>, inferred: bool, limit: u64) -> Value {
    let unavailable = file.sha256.is_none();
    let limitations = if unavailable { vec![file.error.as_deref().unwrap_or("Source bytes unavailable")] }
        else if inferred { vec!["Relative source resolution is inferred; package exports, tsconfig aliases, loader mutation and runtime execution are unproven."] }
        else if file.parse_errors > 0 { vec!["Parser diagnostics make recovered syntax facts partial."] }
        else { vec![] };
    let location = match location {
        Some(location) => json!({"available":true,"value":{"kind":"source-range","source":file.path,"start":location.start,"end":location.end}}),
        None => json!({"available":true,"value":{"kind":"artifact-path","path":file.path}}),
    };
    json!({
        "authority":if unavailable { "unknown" } else if inferred { "static-relationship-inference" } else { "ast-static-analysis" },
        "state":if unavailable { "unavailable" } else if inferred { "inferred" } else { "observed" },
        "confidence":if unavailable { "unknown" } else if inferred { "medium" } else { "exact" },
        "artifact":match &file.sha256 { Some(sha) => json!({"available":true,"artifact_id":format!("art_{sha}"),"sha256":sha}), None => json!({"available":false,"reason":"not-observed","detail":file.error.as_deref().unwrap_or("Source unavailable")}) },
        "location":location,
        "extractor":{"name":"rea-fast","version":env!("CARGO_PKG_VERSION"),"operation":"javascript-structural-analysis","executable_sha256":null},
        "coverage":coverage(if unavailable { "unavailable" } else if file.parse_errors > 0 { "partial" } else { "complete" },limit),
        "limitations":limitations,"evidence_ids":[]
    })
}
fn identity(file: &FileAnalysis) -> Value {
    match &file.sha256 {
        Some(sha) => json!({"strategy":"canonical-path","stability":"artifact-version","artifact_sha256":sha,"path":file.path}),
        None => json!({"strategy":"observation-fingerprint","stability":"observation-only","observation_sha256":digest(file.path.as_bytes()),"scope":"unavailable-source"}),
    }
}

struct Graph<'a> {
    files: &'a [FileAnalysis],
    dependencies: &'a [Vec<Dependency<'a>>],
    ids: Vec<String>,
    node_order: Vec<usize>,
    edge_order: Vec<(String, usize, usize)>,
    limit: u64,
}
impl Graph<'_> {
    fn node(&self, i: usize) -> Value {
        let file = &self.files[i];
        let mut properties = serde_json::to_value(file).expect("File analysis serializes");
        properties["dependencies"] = serde_json::to_value(&self.dependencies[i]).expect("Dependencies serialize");
        let mut observation = json!({"label":file.path,"source_map_reference":null,"properties":properties,"evidence":evidence(file,None,false,self.limit),"identifier_strategy":{"strategy":"semantic-content-sha256","stability":"observation-exact"}});
        let mut semantic = observation.clone();
        semantic["node_id"] = json!(self.ids[i]);
        observation["observation_id"] = json!(semantic_id("jag_observation", &semantic));
        json!({"node_id":self.ids[i],"kind":"source-module","identity":identity(file),"observations":[observation]})
    }
    fn edge(&self, i: usize, d: usize) -> Value {
        let dependency = &self.dependencies[i][d];
        json!({"source_node_id":self.ids[i],"target_node_id":self.ids[dependency.target_index.expect("Resolved edge")],"relation":"imports","properties":{"specifier":dependency.source,"kind":dependency.kind,"type_only":dependency.type_only,"resolution":dependency.resolution},"evidence":evidence(&self.files[i],Some(dependency.location),true,self.limit),"identifier_strategy":{"strategy":"semantic-content-sha256","stability":"relationship-exact"}})
    }
}
struct Nodes<'a>(&'a Graph<'a>);
impl Serialize for Nodes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.node_order.len()))?;
        for &i in &self.0.node_order { seq.serialize_element(&self.0.node(i))?; }
        seq.end()
    }
}
struct Edges<'a>(&'a Graph<'a>);
impl Serialize for Edges<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.edge_order.len()))?;
        for (id, i, d) in &self.0.edge_order {
            let mut edge = self.0.edge(*i,*d);
            edge["edge_id"] = json!(id);
            seq.serialize_element(&edge)?;
        }
        seq.end()
    }
}
#[derive(Serialize)]
struct Content<'a> {
    coverage: Value,
    edges: Edges<'a>,
    limitations: [&'static str; 2],
    nodes: Nodes<'a>,
    root_node_ids: Vec<&'a str>,
    schema: &'static str,
}
struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.0.update(bytes); Ok(bytes.len()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

pub fn write_graph<W: Write>(writer: &mut W, files: &[FileAnalysis], dependencies: &[Vec<Dependency<'_>>], limit: u64) -> Result<(), Box<dyn std::error::Error>> {
    let ids: Vec<_> = files.iter().map(|file| semantic_id("jag_node", &json!({"kind":"source-module","identity":identity(file)}))).collect();
    let mut node_order: Vec<_> = (0..files.len()).collect();
    node_order.sort_unstable_by(|&a,&b| ids[a].cmp(&ids[b]));
    let mut graph = Graph { files, dependencies, ids, node_order, edge_order: vec![], limit };
    for (i, dependencies) in dependencies.iter().enumerate() {
        for (d, dependency) in dependencies.iter().enumerate() {
            if dependency.target_index.is_some_and(|target| target != i) {
                graph.edge_order.push((semantic_id("jag_edge", &graph.edge(i,d)),i,d));
            }
        }
    }
    graph.edge_order.sort_unstable();
    graph.edge_order.dedup_by(|a,b| a.0 == b.0);
    let content = Content {
        coverage:coverage("partial",limit), edges:Edges(&graph),
        limitations:["Structural JS/TS syntax only; Electron, endpoints, runtime, source maps and full REA semantic analysis are not implemented.","The scan honors hidden-file, gitignore and node_modules exclusions; dependencies use relative source-file inference only."],
        nodes:Nodes(&graph),root_node_ids:graph.node_order.iter().map(|&i| graph.ids[i].as_str()).collect(),schema:"JavaScriptApplicationGraph",
    };
    let mut hash = HashWriter(Sha256::new());
    serde_json::to_writer(&mut hash,&content)?;
    let graph_id = format!("jag_{:x}",hash.0.finalize());
    // ponytail: stream facts twice for the commitment; use a temporary spool if hashing dominates large graphs.
    writer.write_all(b"{\"graph_id\":")?;
    serde_json::to_writer(&mut *writer,&graph_id)?;
    writer.write_all(b",")?;
    struct WithoutOpening<'a,W:Write> { writer:&'a mut W, first:bool }
    impl<W:Write> Write for WithoutOpening<'_,W> {
        fn write(&mut self, bytes:&[u8]) -> io::Result<usize> {
            if self.first && !bytes.is_empty() { self.writer.write_all(&bytes[1..])?; self.first=false; Ok(bytes.len()) }
            else { self.writer.write(bytes) }
        }
        fn flush(&mut self) -> io::Result<()> { self.writer.flush() }
    }
    serde_json::to_writer(WithoutOpening { writer, first:true }, &content)?;
    Ok(())
}
