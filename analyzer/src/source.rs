//! Rust source front-end: lightweight heuristic scanner used in `src` mode.
//!
//! This is deliberately not a full rustc HIR/MIR pipeline — it is a fast,
//! dependency-free scanner that recognizes Soroban SDK idioms (storage
//! literals, `require_auth`, token transfers, loops) well enough to feed the
//! source-mode detectors. Full HIR/MIR analysis can be layered on later.

use std::path::{Path, PathBuf};

/// One storage `(spec, key)` use site found in a function.
#[derive(Debug, Clone)]
pub struct StorageUse {
    /// Storage specifier, e.g. `Persistent`.
    pub spec: String,
    /// Source line (1-based).
    pub line: usize,
    /// Raw key expression text if captured (retained for future detectors).
    #[allow(dead_code)]
    pub key_text: Option<String>,
}

/// One loop found in a function.
#[derive(Debug, Clone)]
pub struct LoopSite {
    /// Source line (1-based) of the `loop`/`while`/`for` header.
    pub line: usize,
    /// Expression text at the range end, if any (for `for` loops).
    pub range_end_hint: Option<String>,
}

/// Per-function facts extracted from source.
#[derive(Debug, Clone, Default)]
pub struct SrcFn {
    /// Function name.
    pub name: String,
    /// File the function was found in.
    pub file: String,
    /// Called functions/methods (name fragments).
    pub calls: Vec<String>,
    /// Storage use sites.
    pub storage_literals: Vec<StorageUse>,
    /// Distinct keys observed in Instance storage (heuristic).
    pub instance_keys: Vec<String>,
    /// Lines where a TTL bump/extend call appears.
    pub ttl_bump_lines: Vec<u64>,
    /// (line, operator) of raw arithmetic on amounts.
    pub raw_arith_on_amounts: Vec<(usize, String)>,
    /// Loops in the function.
    pub loops: Vec<LoopSite>,
    /// Whether the function calls require_auth.
    pub has_require_auth: bool,
}

/// All facts collected from a source tree.
#[derive(Debug, Clone, Default)]
pub struct SourceFacts {
    /// Per-file, per-function facts.
    pub functions: Vec<SrcFn>,
    /// Any parse/scan warnings surfaced to the user (retained for future use).
    #[allow(dead_code)]
    pub warnings: Vec<String>,
}

/// Scan a directory tree (or single file) of `.rs` files for Soroban idioms.
pub fn scan_source_tree(root: &Path) -> anyhow::Result<SourceFacts> {
    let mut facts = SourceFacts::default();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&p)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect();
            entries.sort();
            // Skip non-source dirs.
            if entries.iter().any(|e| {
                e.file_name().map(|n| n == "target" || n == ".git").unwrap_or(false)
            }) {
                continue;
            }
            for e in entries {
                stack.push(e);
            }
            continue;
        }
        if p.extension().map(|x| x == "rs").unwrap_or(false) {
            scan_file(&p, &mut facts)?;
        }
    }
    Ok(facts)
}

/// Scan one `.rs` file line by line, tracking the current function context.
fn scan_file(path: &Path, facts: &mut SourceFacts) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let file_str = path.to_string_lossy().to_string();
    let mut current: Option<SrcFn> = None;

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = strip_comment(raw);

        // Function boundaries: `fn name(` at outer level; end at `}` when the
        // brace balance returns to zero. We track a simple balance counter.
        if let Some(f) = fn_header(&line) {
            if let Some(prev) = current.take() {
                facts.functions.push(prev);
            }
            current = Some(SrcFn {
                name: f,
                file: file_str.clone(),
                ..Default::default()
            });
            continue;
        }

        let Some(cur) = current.as_mut() else {
            continue;
        };

        // Brace balance: exit function context when it returns to zero.
        let opens = line.matches('{').count() as i64;
        let closes = line.matches('}').count() as i64;

        if line.contains("require_auth") {
            cur.has_require_auth = true;
            cur.calls.push("require_auth".into());
        }
        if let Some(spec) = storage_spec_from_expr(&line) {
            let key = capture_storage_key(&line);
            cur.storage_literals.push(StorageUse {
                spec: spec.to_string(),
                line: line_no,
                key_text: key.clone(),
            });
            if spec == "Instance" {
                if let Some(k) = key {
                    cur.instance_keys.push(k);
                }
            }
        }
        if line.contains("extend_footprint_ttl") || line.contains("bump_footprint_ttl") {
            cur.ttl_bump_lines.push(line_no as u64);
        }
        for (op, pat) in [
            ("+", "+="),
            ("+", " + "),
            ("-", "-="),
            ("-", " - "),
            ("*", "*="),
            ("*", " * "),
        ] {
            if line.contains(pat) && line_mentions_amount(&line) {
                cur.raw_arith_on_amounts.push((line_no, op.to_string()));
                break;
            }
        }
        if let Some(loop_site) = loop_header(&line, line_no) {
            cur.loops.push(loop_site);
            // Capture the range-end hint on the same or next line.
            if let Some(hint) = capture_range_end(&line) {
                if let Some(last) = cur.loops.last_mut() {
                    last.range_end_hint = Some(hint);
                }
            }
        }
        capture_calls(&line, &mut cur.calls);

        // Exit function at top-level close.
        if closes > opens {
            // Heuristic: any `}` line ends the current function if the line is
            // a lone close or ends an `if` we are not tracking. Simple and
            // conservative: end the function on the first lone `}`.
            let trimmed = line.trim();
            if trimmed == "}" {
                if let Some(done) = current.take() {
                    facts.functions.push(done);
                }
            }
        }
    }
    if let Some(done) = current.take() {
        facts.functions.push(done);
    }
    Ok(())
}

/// Remove `//` comments and string literal contents to reduce false matches.
fn strip_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_str = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_str = !in_str;
                out.push('"');
            }
            '/' if chars.peek() == Some(&'/') && !in_str => break,
            _ => out.push(c),
        }
    }
    out
}

/// Extract a `fn name(` header at outer brace depth, if present.
fn fn_header(line: &str) -> Option<String> {
    let t = line.trim_start();
    let rest = t.strip_prefix("pub ")?.trim_start();
    let rest = rest.strip_prefix("fn ")?.trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '#')
        .collect();
    // `rest` still holds the name; the parameter list starts right after it.
    if name.is_empty() || !rest[name.len()..].trim_start().starts_with('(') {
        return None;
    }
    Some(name)
}

/// Storage specifier recognized on this line?
///
/// The Soroban SDK exposes these as lowercase methods
/// (`env.storage().persistent()`, `.temporary()`, `.instance()`), so match
/// case-insensitively and normalize to the canonical capitalized name.
fn storage_spec_from_expr(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    for (spec, needle) in [
        ("Instance", "instance"),
        ("Persistent", "persistent"),
        ("Temporary", "temporary"),
    ] {
        if lower.contains(needle) {
            return Some(spec);
        }
    }
    None
}

/// Record the bare names of functions/methods called on this line.
///
/// Heuristic: any identifier immediately followed by `(`. Rust keywords are
/// skipped so control flow does not masquerade as a call.
fn capture_calls(line: &str, out: &mut Vec<String>) {
    const KEYWORDS: &[&str] = &[
        "if", "for", "while", "loop", "match", "return", "else", "let", "fn", "in", "as",
    ];
    let bytes = line.as_bytes();
    let mut cursor = 0usize;
    while let Some(rel) = line[cursor..].find('(') {
        let open = cursor + rel;
        let mut start = open;
        while start > 0 {
            let c = bytes[start - 1] as char;
            if c.is_alphanumeric() || c == '_' {
                start -= 1;
            } else {
                break;
            }
        }
        let name = &line[start..open];
        if !name.is_empty()
            && !name.chars().next().unwrap().is_ascii_digit()
            && !KEYWORDS.contains(&name)
        {
            out.push(name.to_string());
        }
        cursor = open + 1;
    }
}

/// Capture the key expression of `env.storage().persistent().set(&KEY, &V)`.
fn capture_storage_key(line: &str) -> Option<String> {
    let idx = line.find("set(&")?;
    let rest = &line[idx + 5..];
    let end = rest.find(',')?;
    let key = rest[..end].trim().trim_end_matches('&').to_string();
    if key.is_empty() {
        None
    } else {
        Some(key)
    }
}

/// Does the line mention an amount-like identifier?
fn line_mentions_amount(line: &str) -> bool {
    line.contains("amount")
        || line.contains("_amt")
        || line.contains("balance")
        || line.contains("supply")
}

/// Recognize a loop header and, for `for` loops, capture the range end.
fn loop_header(line: &str, line_no: usize) -> Option<LoopSite> {
    let t = line.trim_start();
    if t.starts_with("for ") {
        if let Some(in_pos) = t.find(" in ") {
            let after = &t[in_pos + 4..];
            let hint = capture_range_end(after).unwrap_or_else(|| {
                after.split_whitespace().next().unwrap_or("").to_string()
            });
            return Some(LoopSite { line: line_no, range_end_hint: Some(hint) });
        }
        return Some(LoopSite { line: line_no, range_end_hint: None });
    }
    if t.starts_with("while ") || t.starts_with("loop {") || t == "loop {" {
        return Some(LoopSite { line: line_no, range_end_hint: None });
    }
    None
}

/// Capture a numeric or bounded-looking range end from `..end` text.
fn capture_range_end(text: &str) -> Option<String> {
    if let Some(pos) = text.find("..") {
        let rest = &text[pos + 2..];
        let end: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        let end = end.trim_end_matches('.');
        if !end.is_empty() {
            return Some(end.to_string());
        }
    }
    None
}
