mod analyze;
mod graph;

use clap::{Parser, ValueEnum};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::Serialize;
use std::{error::Error, io::{self, Write}, path::{Path, PathBuf}, time::Instant};

#[derive(Parser)]
#[command(version, about = "Parallel, non-executing JavaScript/TypeScript structural analysis")]
struct Cli {
    path: PathBuf,
    #[arg(long, value_enum, default_value = "summary")]
    format: Format,
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Files larger than this limit remain explicitly unavailable.
    #[arg(long, default_value_t = 16_777_216, value_parser = clap::value_parser!(u64).range(1..))]
    max_file_bytes: u64,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format { Summary, Json, JsonSummary }

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

fn supported(path: &Path) -> bool {
    matches!(path.extension().and_then(|s| s.to_str()), Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts"))
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut files = Vec::new();
    for entry in WalkBuilder::new(root).hidden(true).git_ignore(true).require_git(false)
        .filter_entry(|entry| !entry.file_type().is_some_and(|t| t.is_dir()) || !matches!(entry.file_name().to_str(), Some("node_modules" | ".git")))
        .build() {
        let entry = entry?;
        if entry.file_type().is_some_and(|t| t.is_file()) && supported(entry.path()) {
            files.push(entry.into_path());
        }
    }
    files.sort();
    Ok(files)
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let start = Instant::now();
    let input = cli.path.canonicalize()?;
    if input.is_file() && !supported(&input) { return Err("Expected a JS/TS file or directory".into()); }
    let root = if input.is_file() { input.parent().ok_or("File has no parent")? } else { &input };
    let files = collect_files(&input)?;
    if files.is_empty() { return Err("No JS/TS files matched the ignore rules".into()); }
    let pool = rayon::ThreadPoolBuilder::new().num_threads(cli.threads).build()?;
    let results: Vec<_> = pool.install(|| files.par_iter().map(|path| analyze::analyze_file(path, root, cli.max_file_bytes)).collect());
    let dependencies = graph::dependencies(&results);
    let mut summary = Summary { total_files: results.len(), threads_used: pool.current_num_threads(), ..Summary::default() };
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
    summary.internal_dependencies = dependencies.iter().flatten().filter(|d| d.target.is_some()).count();
    summary.unresolved_dependencies = dependencies.iter().filter(|d| d.target.is_none()).count();
    let elapsed = start.elapsed().as_secs_f64();
    summary.elapsed_ms = elapsed * 1000.0;
    summary.files_per_second = summary.total_files as f64 / elapsed;
    summary.mb_per_second = summary.total_bytes as f64 / 1_048_576.0 / elapsed;
    let mut out = io::BufWriter::new(io::stdout().lock());
    match cli.format {
        Format::Json => graph::write_graph(&mut out, &results, &dependencies, cli.max_file_bytes)?,
        Format::JsonSummary => serde_json::to_writer(&mut out, &summary)?,
        Format::Summary => write!(out,
            "Files       {:>12}\nLOC         {:>12}\nBytes       {:>12}\nImports     {:>12}\nExports     {:>12}\nFunctions   {:>12}\nClasses     {:>12}\nSymbols     {:>12}\nParse errors{:>12}\nUnavailable {:>12}\nInternal dependencies {:>6}\nUnresolved/external   {:>6}\nThreads     {:>12}\nAnalysis ms {:>12.2}\nFiles/s     {:>12.0}\nMiB/s       {:>12.2}\n",
            summary.total_files, summary.total_lines, summary.total_bytes, summary.total_imports,
            summary.total_exports, summary.total_functions, summary.total_classes, summary.total_symbols,
            summary.parse_errors, summary.unavailable_files, summary.internal_dependencies,
            summary.unresolved_dependencies, summary.threads_used, summary.elapsed_ms,
            summary.files_per_second, summary.mb_per_second)?,
    }
    writeln!(out)?;
    out.flush()?;
    if summary.unavailable_files > 0 { return Err(format!("{} files unavailable; output retains partial results", summary.unavailable_files).into()); }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        if error.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe) { return; }
        eprintln!("rea-fast: {error}");
        std::process::exit(1);
    }
}
