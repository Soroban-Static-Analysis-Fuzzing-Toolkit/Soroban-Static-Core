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
    /// Rule ids suppressed for this function by an inline
    /// `soroban-analyzer: allow(...)` directive.
    pub allowed_rules: Vec<String>,
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
                e.file_name()
                    .map(|n| n == "target" || n == ".git")
                    .unwrap_or(false)
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
///
/// Function bodies are delimited by tracking brace depth from the opening
/// brace, so a nested block that closes on its own line (`if`, `match`, `for`)
/// no longer truncates the function and drops the facts that follow it.
fn scan_file(path: &Path, facts: &mut SourceFacts) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let file_str = path.to_string_lossy().to_string();
    let mut state = ScanState::default();
    let mut current: Option<SrcFn> = None;
    // Brace depth relative to the current function's opening brace.
    let mut depth: i32 = 0;
    let mut body_started = false;

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;

        // Suppression directives live in comments, so read the raw line first.
        if let Some(rules) = parse_allow_directive(raw) {
            if let Some(cur) = current.as_mut() {
                cur.allowed_rules.extend(rules);
            }
        }

        let line = state.strip(raw);

        // Start a function only when not already inside one.
        if let Some(name) = fn_header(&line) {
            if current.is_none() {
                current = Some(SrcFn {
                    name,
                    file: file_str.clone(),
                    ..Default::default()
                });
                let (opens, closes) = brace_delta(&line);
                body_started = opens > 0;
                depth = opens - closes;
                // A single-line `fn f() {}` is complete on the header line.
                if body_started && depth <= 0 {
                    push_function(&mut current, facts);
                    body_started = false;
                }
                continue;
            }
        }

        let Some(cur) = current.as_mut() else {
            continue;
        };

        collect_line_facts(&line, line_no, cur);

        let (opens, closes) = brace_delta(&line);
        if body_started {
            depth += opens - closes;
            if depth <= 0 {
                push_function(&mut current, facts);
                body_started = false;
            }
        } else if opens > 0 {
            // Header whose brace was on a later line.
            body_started = true;
            depth = opens - closes;
            if depth <= 0 {
                push_function(&mut current, facts);
                body_started = false;
            }
        }
    }
    if let Some(done) = current.take() {
        facts.functions.push(done);
    }
    Ok(())
}

/// Finish the in-progress function, if any.
fn push_function(current: &mut Option<SrcFn>, facts: &mut SourceFacts) {
    if let Some(done) = current.take() {
        facts.functions.push(done);
    }
}

/// Collect the Soroban idioms found on one cleaned source line.
fn collect_line_facts(line: &str, line_no: usize, cur: &mut SrcFn) {
    if line.contains("require_auth") {
        cur.has_require_auth = true;
        cur.calls.push("require_auth".into());
    }
    if let Some(spec) = storage_spec_from_expr(line) {
        let key = capture_storage_key(line);
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
        if line.contains(pat) && line_mentions_amount(line) {
            cur.raw_arith_on_amounts.push((line_no, op.to_string()));
            break;
        }
    }
    if let Some(loop_site) = loop_header(line, line_no) {
        cur.loops.push(loop_site);
        if let Some(hint) = capture_range_end(line) {
            if let Some(last) = cur.loops.last_mut() {
                last.range_end_hint = Some(hint);
            }
        }
    }
    capture_calls(line, &mut cur.calls);
}

/// Number of `{` and `}` on a line.
fn brace_delta(line: &str) -> (i32, i32) {
    let opens = line.chars().filter(|c| *c == '{').count() as i32;
    let closes = line.chars().filter(|c| *c == '}').count() as i32;
    (opens, closes)
}

/// Parse an inline `soroban-analyzer: allow(SOR-101, SOR-103)` directive.
fn parse_allow_directive(line: &str) -> Option<Vec<String>> {
    const MARKER: &str = "soroban-analyzer: allow(";
    let start = line.find(MARKER)? + MARKER.len();
    let end = start + line[start..].find(')')?;
    let rules: Vec<String> = line[start..end]
        .split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    (!rules.is_empty()).then_some(rules)
}

/// Lexer-style state persisted across lines.
///
/// The previous per-line stripper toggled a `"` flag, so escaped quotes and
/// char literals desynchronised it and block comments were never removed.
#[derive(Default)]
struct ScanState {
    in_block_comment: bool,
}

impl ScanState {
    /// Replace comment bodies and string/char literal contents with spaces,
    /// preserving line length so positions and surrounding code stay intact.
    fn strip(&mut self, line: &str) -> String {
        let chars: Vec<char> = line.chars().collect();
        let mut out = String::with_capacity(line.len());
        let mut i = 0;
        while i < chars.len() {
            if self.in_block_comment {
                if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    self.in_block_comment = false;
                    out.push_str("  ");
                    i += 2;
                } else {
                    out.push(' ');
                    i += 1;
                }
                continue;
            }
            if chars[i] == '/' && chars.get(i + 1) == Some(&'/') {
                break;
            }
            if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                self.in_block_comment = true;
                out.push_str("  ");
                i += 2;
                continue;
            }
            match chars[i] {
                '"' => {
                    out.push('"');
                    i += 1;
                    while i < chars.len() {
                        if chars[i] == '\\' && i + 1 < chars.len() {
                            out.push_str("  ");
                            i += 2;
                        } else if chars[i] == '"' {
                            out.push('"');
                            i += 1;
                            break;
                        } else {
                            out.push(' ');
                            i += 1;
                        }
                    }
                }
                '\'' => match char_literal_len(&chars[i..]) {
                    Some(len) => {
                        for _ in 0..len {
                            out.push(' ');
                        }
                        i += len;
                    }
                    None => {
                        // A lifetime or bare apostrophe: keep it verbatim.
                        out.push('\'');
                        i += 1;
                    }
                },
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        out
    }
}

/// Length in chars of a char literal starting at `s[0] == '\''`, if any.
///
/// Returns `None` for lifetimes such as `'a`, which must not be treated as
/// literals.
fn char_literal_len(s: &[char]) -> Option<usize> {
    match s.get(1)? {
        '\\' => {
            if s.get(2) == Some(&'u') {
                let close = s.iter().position(|c| *c == '}')?;
                (s.get(close + 1) == Some(&'\'')).then_some(close + 2)
            } else {
                (s.get(3) == Some(&'\'')).then_some(4)
            }
        }
        '\'' => None,
        _ => (s.get(2) == Some(&'\'')).then_some(3),
    }
}

/// Extract a function name from a definition line, if present.
///
/// Recognises visibility (`pub`, `pub(crate)`, …) and the qualifiers Soroban
/// contracts use (`async`, `const`, `unsafe`), plus optional generics. The old
/// implementation only matched `pub fn`, so private helpers were skipped.
fn fn_header(line: &str) -> Option<String> {
    let t = line.trim_start();
    let at = find_fn_keyword(t)?;
    let after = t[at + "fn ".len()..].trim_start();
    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    let tail = after[name.len()..].trim_start();
    let tail = match tail.strip_prefix('<') {
        Some(rest) => {
            let close = matching_angle(rest)?;
            rest[close + 1..].trim_start()
        }
        None => tail,
    };
    tail.starts_with('(').then_some(name)
}

/// Byte index of the `fn ` keyword in `line`, if everything preceding it is a
/// visibility/qualifier prefix.
fn find_fn_keyword(line: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = line[from..].find("fn ") {
        let at = from + rel;
        if is_qualifier_prefix(&line[..at]) {
            return Some(at);
        }
        from = at + "fn ".len();
    }
    None
}

/// Whether `prefix` consists only of tokens allowed before `fn`.
fn is_qualifier_prefix(prefix: &str) -> bool {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return true;
    }
    let tokens = match prefix.strip_prefix("pub(") {
        Some(rest) => match rest.find(')') {
            Some(close) => rest[close + 1..].trim_start(),
            None => return false,
        },
        None => prefix
            .strip_prefix("pub")
            .map(str::trim_start)
            .unwrap_or(prefix),
    };
    tokens.split_whitespace().all(|tok| {
        matches!(tok, "async" | "const" | "unsafe" | "extern" | "default") || tok.starts_with('"')
    })
}

/// Offset of the `>` matching a leading `<` (the `<` itself is excluded).
fn matching_angle(rest: &str) -> Option<usize> {
    let mut depth = 1u32;
    for (i, c) in rest.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
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
            let hint = capture_range_end(after)
                .unwrap_or_else(|| after.split_whitespace().next().unwrap_or("").to_string());
            return Some(LoopSite {
                line: line_no,
                range_end_hint: Some(hint),
            });
        }
        return Some(LoopSite {
            line: line_no,
            range_end_hint: None,
        });
    }
    if t.starts_with("while ") || t.starts_with("loop {") || t == "loop {" {
        return Some(LoopSite {
            line: line_no,
            range_end_hint: None,
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scan(src: &str) -> SourceFacts {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("contract.rs");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(src.as_bytes()).expect("write");
        scan_source_tree(dir.path()).expect("scan")
    }

    fn function<'a>(facts: &'a SourceFacts, name: &str) -> &'a SrcFn {
        let names: Vec<&str> = facts.functions.iter().map(|f| f.name.as_str()).collect();
        facts
            .functions
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("function {name} not found in {names:?}"))
    }

    #[test]
    fn scans_private_and_qualified_functions() {
        let facts = scan(
            r#"
            fn private_helper(env: Env) {
                env.storage().persistent().set(&K, &1);
            }
            pub(crate) async fn also_private(env: Env) {
                env.storage().temporary().set(&K, &2);
            }
            pub fn entry(env: Env) {
                env.storage().instance().get(&K);
            }
            "#,
        );
        assert_eq!(
            function(&facts, "private_helper").storage_literals[0].spec,
            "Persistent"
        );
        assert_eq!(
            function(&facts, "also_private").storage_literals[0].spec,
            "Temporary"
        );
        assert!(facts.functions.iter().any(|f| f.name == "entry"));
    }

    #[test]
    fn nested_block_does_not_truncate_function() {
        let facts = scan(
            r#"
            pub fn entry(env: Env, ids: Vec<u32>) {
                if ids.is_empty() {
                    return;
                }
                env.storage().persistent().set(&K, &1);
                for id in ids.iter() {
                    let _ = id;
                }
            }
            "#,
        );
        let f = function(&facts, "entry");
        assert_eq!(
            f.storage_literals.len(),
            1,
            "storage after the nested block must be seen"
        );
        assert_eq!(f.loops.len(), 1, "loop after the nested block must be seen");
    }

    #[test]
    fn escaped_quotes_and_char_literals_do_not_desync() {
        let facts = scan(
            r#"
            pub fn entry(env: Env) {
                let _s = "a \" quoted } brace";
                let _c = '"';
                env.storage().persistent().set(&K, &1);
            }
            "#,
        );
        assert_eq!(function(&facts, "entry").storage_literals.len(), 1);
    }

    #[test]
    fn block_comments_are_ignored() {
        let facts = scan(
            r#"
            pub fn entry(env: Env) {
                /* env.storage().temporary().set(&K, &9);
                   require_auth(); */
                env.storage().persistent().set(&K, &1);
            }
            "#,
        );
        let f = function(&facts, "entry");
        assert!(
            !f.has_require_auth,
            "require_auth inside a comment must be ignored"
        );
        assert_eq!(f.storage_literals.len(), 1);
        assert_eq!(f.storage_literals[0].spec, "Persistent");
    }

    #[test]
    fn allow_directive_is_parsed() {
        assert_eq!(
            parse_allow_directive("// soroban-analyzer: allow(SOR-101, SOR-103)"),
            Some(vec!["SOR-101".to_string(), "SOR-103".to_string()])
        );
        assert_eq!(parse_allow_directive("// just a comment"), None);
    }

    #[test]
    fn allow_directive_attaches_to_the_containing_function() {
        let facts = scan(
            r#"
            pub fn entry(env: Env) {
                // soroban-analyzer: allow(SOR-101)
                env.storage().persistent().set(&K, &1);
            }
            "#,
        );
        assert_eq!(
            function(&facts, "entry").allowed_rules,
            vec!["SOR-101".to_string()]
        );
    }

    /// Deterministic xorshift64; enough for a fuzz smoke test without pulling
    /// in a fuzzing dependency.
    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn adversarial_lines_never_panic() {
        // The scanner runs over untrusted source, so the lexing helpers must
        // never panic on malformed input.
        let alphabet: Vec<char> = "abcxyz(){}[]<>,;'\"\\/ *\n#pubfnasyncunsafeconst"
            .chars()
            .collect();
        let mut state = 0x1234_5678_9abc_def0_u64;
        let mut scan_state = ScanState::default();
        for _ in 0..4_000 {
            let len = (next_random(&mut state) % 48) as usize;
            let line: String = (0..len)
                .map(|_| alphabet[(next_random(&mut state) as usize) % alphabet.len()])
                .collect();
            let cleaned = scan_state.strip(&line);
            let _ = fn_header(&cleaned);
            let _ = brace_delta(&cleaned);
            let _ = parse_allow_directive(&line);
            let _ = char_literal_len(&line.chars().collect::<Vec<_>>());
            let _ = loop_header(&cleaned, 1);
            let _ = storage_spec_from_expr(&cleaned);
            let _ = capture_storage_key(&cleaned);
        }
    }
}
