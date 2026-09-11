//! Internal module registry. Kept private; `pub use` re-exports the public API.

mod analyze;
mod budget;
mod detectors;
mod rules;
mod source;
mod wasm;

pub use analyze::{analyze_module, analyze_source, AnalysisOutput, AnalysisSummary, InputMode};
pub use budget::{budget_module, format_budget_report, BudgetReport, EntrypointBudget, Verdict};
pub use detectors::{all_rules, RuleKind, RuleMeta};
pub use rules::{
    render_config_template, RuleOverride, RulesConfig, DEFAULT_CONFIG_TOML, RULES_SCHEMA_VERSION,
};
