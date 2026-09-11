//! End-to-end tests for the `soroban-analyzer` binary.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn analyzer() -> Command {
    Command::cargo_bin("soroban-analyzer").expect("binary built")
}

#[test]
fn lists_rules() {
    analyzer()
        .arg("--list-rules")
        .assert()
        .success()
        .stdout(predicate::str::contains("SOR-101"))
        .stdout(predicate::str::contains("SOR-104"))
        .stdout(predicate::str::contains("unbounded-loop-over-storage"));
}

#[test]
fn prints_default_config() {
    analyzer()
        .arg("--init-config")
        .assert()
        .success()
        .stdout(predicate::str::contains("schema_version = \"1\""));
}

#[test]
fn analyzes_wasm_and_fails_on_error() {
    analyzer()
        .arg(fixture("contract.wat"))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("SOR-101"))
        .stdout(predicate::str::contains("SOR-106"))
        .stdout(predicate::str::contains("mint"));
}

#[test]
fn analyzes_source_directory() {
    analyzer()
        .arg(fixture("source"))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("SOR-101"))
        .stdout(predicate::str::contains("SOR-103"))
        .stdout(predicate::str::contains("SOR-104"));
}

#[test]
fn fail_on_never_exits_zero() {
    analyzer()
        .args(["--fail-on", "never"])
        .arg(fixture("contract.wat"))
        .assert()
        .success();
}

#[test]
fn config_can_disable_and_reseverity_rules() {
    analyzer()
        .arg("--config")
        .arg(fixture("soroban-analyzer.toml"))
        .arg("--fail-on")
        .arg("error")
        .arg(fixture("contract.wat"))
        .assert()
        .success()
        .stdout(predicate::str::contains("SOR-101"))
        .stdout(predicate::str::contains("SOR-106").not());
}

#[test]
fn json_output_is_structured() {
    let out = analyzer()
        .args(["--format", "json"])
        .arg(fixture("contract.wat"))
        .output()
        .expect("run analyzer");
    assert!(out.status.success() || out.status.code() == Some(1));

    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let first = &value[0];
    assert_eq!(first["summary"]["mode"], "wasm");
    assert!(first["findings"].as_array().is_some_and(|f| !f.is_empty()));
}

#[test]
fn sarif_output_is_valid_sarif() {
    let out = analyzer()
        .args(["--format", "sarif"])
        .arg(fixture("contract.wat"))
        .output()
        .expect("run analyzer");

    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(value["version"], "2.1.0");
    assert_eq!(
        value["runs"][0]["tool"]["driver"]["name"],
        "soroban-analyzer"
    );
    assert!(value["runs"][0]["results"]
        .as_array()
        .is_some_and(|r| !r.is_empty()));
}

#[test]
fn missing_target_reports_usage_error() {
    analyzer()
        .arg(fixture("does-not-exist.wasm"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn mode_mismatch_is_rejected() {
    analyzer()
        .args(["--mode", "source"])
        .arg(fixture("contract.wat"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not Rust source"));

    analyzer()
        .args(["--mode", "wasm"])
        .arg(fixture("source/token.rs"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a wasm module"));
}

#[test]
fn explicit_mode_matching_the_target_succeeds() {
    analyzer()
        .args(["--mode", "wasm", "--fail-on", "never"])
        .arg(fixture("contract.wat"))
        .assert()
        .success();

    analyzer()
        .args(["--mode", "source", "--fail-on", "never"])
        .arg(fixture("source"))
        .assert()
        .success();
}

#[test]
fn init_config_documents_every_rule() {
    let out = analyzer()
        .arg("--init-config")
        .output()
        .expect("run analyzer");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("utf8");
    for id in [
        "SOR-101", "SOR-102", "SOR-103", "SOR-104", "SOR-105", "SOR-106",
    ] {
        assert!(text.contains(id), "--init-config is missing {id}");
    }
    assert!(text.contains("schema_version"));
}

#[test]
fn unknown_rule_id_in_config_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = dir.path().join("soroban-analyzer.toml");
    std::fs::write(
        &cfg,
        "schema_version = \"1\"\n[rules.SOR-999]\nenabled = false\n",
    )
    .expect("write config");

    analyzer()
        .arg("--config")
        .arg(&cfg)
        .arg(fixture("contract.wat"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown rule"));
}

#[test]
fn no_budget_suppresses_the_budget_block() {
    let with = analyzer()
        .arg(fixture("contract.wat"))
        .output()
        .expect("run analyzer");
    let without = analyzer()
        .args(["--no-budget"])
        .arg(fixture("contract.wat"))
        .output()
        .expect("run analyzer");

    assert!(String::from_utf8_lossy(&with.stdout).contains("budget:"));
    assert!(!String::from_utf8_lossy(&without.stdout).contains("budget:"));
}

#[test]
fn json_report_includes_budget_limits() {
    let out = analyzer()
        .args(["--format", "json"])
        .arg(fixture("contract.wat"))
        .output()
        .expect("run analyzer");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");

    let limits = &value[0]["budget"]["limits"];
    assert!(limits["max_reads"].as_u64().is_some());
    assert!(limits["max_instructions"].as_u64().is_some());
    assert!(value[0]["summary"]["entrypoints"].as_u64().unwrap_or(0) >= 1);
}

#[test]
fn sarif_information_uri_points_at_the_repository() {
    let out = analyzer()
        .args(["--format", "sarif"])
        .arg(fixture("contract.wat"))
        .output()
        .expect("run analyzer");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let uri = value["runs"][0]["tool"]["driver"]["informationUri"]
        .as_str()
        .expect("informationUri present");
    assert!(uri.contains("Soroban-Static-Core"), "{uri}");
}

#[test]
fn delegated_auth_is_not_flagged() {
    let out = analyzer()
        .args(["--format", "json"])
        .arg(fixture("delegated-auth.wat"))
        .output()
        .expect("run analyzer");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let findings = value[0]["findings"].as_array().expect("findings array");
    assert!(
        !findings.iter().any(|f| f["rule_id"] == "SOR-101"),
        "delegated auth must not be flagged: {findings:?}"
    );
}

#[test]
fn inline_allow_directive_suppresses_one_function_only() {
    let out = analyzer()
        .args(["--format", "json"])
        .arg(fixture("suppressed"))
        .output()
        .expect("run analyzer");
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let findings = value[0]["findings"].as_array().expect("findings array");

    let arith: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "SOR-103")
        .collect();
    assert!(
        arith
            .iter()
            .any(|f| f["location"]["function"] == "flagged_pay"),
        "the un-suppressed function should still be flagged: {findings:?}"
    );
    assert!(
        !arith
            .iter()
            .any(|f| f["location"]["function"] == "allowed_pay"),
        "the allow directive should suppress the finding: {findings:?}"
    );
}

#[test]
fn fail_on_warning_counts_warnings() {
    // SOR-106 is a warning in the fixture; `--fail-on warning` must catch it.
    analyzer()
        .args(["--fail-on", "warning"])
        .arg(fixture("contract.wat"))
        .assert()
        .code(1);
}
