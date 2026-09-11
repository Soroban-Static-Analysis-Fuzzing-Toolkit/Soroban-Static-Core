//! End-to-end tests for the `soroban-analyzer` binary.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(rel)
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
    assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "soroban-analyzer");
    assert!(
        value["runs"][0]["results"]
            .as_array()
            .is_some_and(|r| !r.is_empty())
    );
}

#[test]
fn missing_target_reports_usage_error() {
    analyzer()
        .arg(fixture("does-not-exist.wasm"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}
