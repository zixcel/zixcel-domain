use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn cli_reports_missing_credentials_without_echoing_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_zixcel-domain"))
        .arg("valuedomain-domains")
        .env_remove("VALUEDOMAIN_ACCESS_TOKEN")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "credential_missing");
}

#[test]
fn invalid_manifest_is_not_printed_to_logs() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zixcel-domain"))
        .arg("validate-bindings")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"secret-invalid-input")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-invalid-input"));
}
