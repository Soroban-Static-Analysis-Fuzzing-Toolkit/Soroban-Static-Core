//! `soroban-analyzer` CLI: static analysis and resource budgeting for Soroban
//! contracts, from either compiled wasm or Rust source.
//!
//! ```text
//! soroban-analyzer contract.wasm
//! soroban-analyzer --mode source contracts/token/src
//! soroban-analyzer --format sarif --fail-on warning target/contract.wasm
//! ```

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use soroban_analyzer::{
    all_rules, analyze_module, analyze_source, format_budget_report, render_config_template,
    AnalysisOutput, InputMode, RuleKind, RulesConfig,
};
use soroban_common::{sarif::SarifLog, Finding, NetworkLimits, Severity};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// How the input is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// Infer from the file extension (`.wasm`/`.wat` → wasm, `.rs` → source).
    Auto,
    /// Compiled wasm (or WAT) modules.
    Wasm,
    /// Rust source files or directories.
    Source,
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable report.
    Text,
    /// Machine-readable JSON.
    Json,
    /// SARIF 2.1.0 for GitHub code scanning.
    Sarif,
}

/// Minimum severity that yields a non-zero exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOn {
    /// Never fail the build.
    Never,
    /// Fail on any finding.
    Note,
    /// Fail on warnings and errors.
    Warning,
    /// Fail on errors only (default).
    Error,
}

impl FailOn {
    fn threshold(self) -> Option<Severity> {
        match self {
            FailOn::Never => None,
            FailOn::Note => Some(Severity::Note),
            FailOn::Warning => Some(Severity::Warning),
            FailOn::Error => Some(Severity::Error),
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "soroban-analyzer",
    version,
    about = "Static analysis and resource budgeting for Soroban smart contracts"
)]
struct Cli {
    /// Files or directories to analyze.
    #[arg(value_name = "TARGET")]
    targets: Vec<PathBuf>,

    /// Input interpretation.
    #[arg(short, long, value_enum, default_value = "auto")]
    mode: Mode,

    /// Output format.
    #[arg(short, long, value_enum, default_value = "text")]
    format: Format,

    /// Rule configuration file (TOML). See `--init-config`.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Minimum severity that produces a non-zero exit status.
    #[arg(long, value_enum, default_value = "error")]
    fail_on: FailOn,

    /// Omit the resource-budget report from text output.
    #[arg(long)]
    no_budget: bool,

    /// Print the registered rules and exit.
    #[arg(long)]
    list_rules: bool,

    /// Print the default rule configuration to stdout and exit.
    #[arg(long)]
    init_config: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: &Cli) -> Result<ExitCode> {
    if cli.list_rules {
        print_rules();
        return Ok(ExitCode::SUCCESS);
    }
    if cli.init_config {
        print!("{}", render_config_template());
        return Ok(ExitCode::SUCCESS);
    }
    if cli.targets.is_empty() {
        bail!("no targets given; pass a .wasm/.wat file or a Rust source path");
    }

    let cfg = load_config(cli.config.as_deref())?;
    let jobs = collect_jobs(&cli.targets, cli.mode)?;
    let limits = NetworkLimits::mainnet();

    // Analyze targets in parallel; `collect` preserves input order.
    let results: Vec<Result<AnalysisOutput>> = jobs
        .par_iter()
        .map(|(path, mode)| match mode {
            Mode::Wasm => analyze_module(path, &cfg, limits),
            Mode::Source => analyze_source(path, &cfg),
            Mode::Auto => unreachable!("mode resolved before scheduling"),
        })
        .collect();
    let outputs: Vec<AnalysisOutput> = results.into_iter().collect::<Result<_>>()?;

    match cli.format {
        Format::Text => print_text(&outputs, cli.no_budget),
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&outputs)?);
        }
        Format::Sarif => {
            let findings: Vec<&Finding> = outputs.iter().flat_map(|o| &o.findings).collect();
            let refs: Vec<Finding> = findings.into_iter().cloned().collect();
            let log = SarifLog::from_findings("soroban-analyzer", env!("CARGO_PKG_VERSION"), &refs);
            println!("{}", log.to_json_pretty()?);
        }
    }

    let failed = match cli.fail_on.threshold() {
        Some(threshold) => outputs
            .iter()
            .flat_map(|o| &o.findings)
            .any(|f| f.severity >= threshold),
        None => false,
    };
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn load_config(path: Option<&Path>) -> Result<RulesConfig> {
    match path {
        None => Ok(RulesConfig::default()),
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("read config {}", p.display()))?;
            RulesConfig::from_toml_str(&text)
                .with_context(|| format!("parse config {}", p.display()))
        }
    }
}

/// Expand the user's targets into concrete (path, mode) analysis jobs.
fn collect_jobs(targets: &[PathBuf], mode: Mode) -> Result<Vec<(PathBuf, Mode)>> {
    let mut jobs = Vec::new();
    for target in targets {
        if !target.exists() {
            bail!("target not found: {}", target.display());
        }
        validate_mode(target, mode)?;
        match resolve_mode(target, mode)? {
            // A wasm directory expands to every module it contains.
            resolved @ Mode::Wasm if target.is_dir() => {
                let mut found = Vec::new();
                collect_files(target, &["wasm", "wat"], &mut found)?;
                if found.is_empty() {
                    bail!("no .wasm/.wat files under {}", target.display());
                }
                found.sort();
                jobs.extend(found.into_iter().map(|p| (p, resolved)));
            }
            Mode::Auto => bail!("could not resolve input mode for {}", target.display()),
            resolved => jobs.push((target.clone(), resolved)),
        }
    }
    if jobs.is_empty() {
        bail!("no targets to analyze");
    }
    Ok(jobs)
}

/// Reject an explicit `--mode` that cannot match the target.
///
/// Without this, `--mode source contract.wasm` reads the binary as UTF-8 text
/// and reports "no findings" — a clean-looking result that silently analyzed
/// nothing at all.
fn validate_mode(path: &Path, mode: Mode) -> Result<()> {
    if mode == Mode::Auto {
        return Ok(());
    }
    let ext = path.extension().and_then(|e| e.to_str());
    match (mode, ext, path.is_dir()) {
        (Mode::Source, Some("wasm" | "wat"), false) => bail!(
            "{} is a wasm module, not Rust source; drop --mode source",
            path.display()
        ),
        (Mode::Wasm, Some("rs"), false) => bail!(
            "{} is Rust source, not a wasm module; drop --mode wasm",
            path.display()
        ),
        (Mode::Source, _, true) if !contains_ext(path, "rs") => {
            bail!("no .rs files under {} (--mode source)", path.display())
        }
        _ => Ok(()),
    }
}

/// Resolve `Auto` mode from the target's file extension or directory contents.
fn resolve_mode(path: &Path, mode: Mode) -> Result<Mode> {
    if mode != Mode::Auto {
        return Ok(mode);
    }
    if path.is_dir() {
        if contains_ext(path, "rs") {
            return Ok(Mode::Source);
        }
        if contains_ext(path, "wasm") || contains_ext(path, "wat") {
            return Ok(Mode::Wasm);
        }
        bail!(
            "cannot infer input mode for directory {}; pass --mode",
            path.display()
        );
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some("wasm") | Some("wat") => Ok(Mode::Wasm),
        Some("rs") => Ok(Mode::Source),
        _ => bail!(
            "cannot infer input mode for {}; pass --mode",
            path.display()
        ),
    }
}

/// Recursively collect files under `root` whose extension is in `exts`.
fn collect_files(root: &Path, exts: &[&str], out: &mut Vec<PathBuf>) -> Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            let skip = p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == "target" || n == ".git")
                .unwrap_or(false);
            if skip {
                continue;
            }
            for entry in
                std::fs::read_dir(&p).with_context(|| format!("read dir {}", p.display()))?
            {
                stack.push(entry?.path());
            }
        } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            if exts.contains(&ext) {
                out.push(p);
            }
        }
    }
    Ok(())
}

fn contains_ext(root: &Path, ext: &str) -> bool {
    let mut found = Vec::new();
    collect_files(root, &[ext], &mut found)
        .map(|()| !found.is_empty())
        .unwrap_or(false)
}

fn print_rules() {
    for rule in all_rules() {
        let kind = match rule.kind {
            RuleKind::Wasm => "wasm",
            RuleKind::Source => "source",
            RuleKind::Both => "both",
        };
        println!(
            "{:<8} {:<7} {:<6} {}",
            rule.id, rule.default_severity, kind, rule.name
        );
        println!("         {}", rule.description);
    }
}

fn print_text(outputs: &[AnalysisOutput], no_budget: bool) {
    let mut total = 0usize;
    for out in outputs {
        let mode = match out.summary.mode {
            InputMode::Wasm => "wasm",
            InputMode::Source => "source",
        };
        println!("== {} ({mode}) ==", out.summary.target);
        if out.findings.is_empty() {
            println!("  no findings");
        }
        for f in &out.findings {
            println!("{}", format_finding(f));
        }
        total += out.findings.len();

        if !no_budget {
            if let Some(report) = &out.budget {
                print!("{}", format_budget_report(report));
            }
        }
        println!();
    }
    println!("{total} finding(s) across {} target(s)", outputs.len());
}

fn format_finding(f: &Finding) -> String {
    let mut loc = f.location.file.clone();
    if let Some(line) = f.location.line {
        loc = format!("{loc}:{line}");
    }
    let func = match &f.location.function {
        Some(name) => format!(" [{name}]"),
        None => String::new(),
    };
    format!(
        "  {:<7} {:<8} {loc}{func}  {}",
        f.severity.to_string(),
        f.rule_id,
        f.message
    )
}
