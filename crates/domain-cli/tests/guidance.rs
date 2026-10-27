use serde_json::{Value, json};
use std::process::Command;
#[test]
fn metadata_is_credential_free_complete_for_manifest_and_source_owned() {
    let manifest = zixcel_domain_cli::manifest();
    assert_eq!(manifest.protocol, "zix-provider/v2");
    let catalog = zixcel_domain_cli::guidance().unwrap();
    assert!(catalog.validate());
    for c in &manifest.commands {
        assert!(
            catalog
                .entries
                .iter()
                .any(|g| g.operation == c.id && g.selectors.is_empty())
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_zix-domain"))
        .arg("--guidance")
        .env_clear()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let exported: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(exported, serde_json::to_value(catalog).unwrap());
    assert!(output.stderr.is_empty());
}
#[test]
fn dns_plans_require_authority_and_keep_unknown_write_recovery_separate() {
    let c = zixcel_domain_cli::guidance().unwrap();
    let g = c.select("dns.records.plan", &Default::default()).unwrap();
    assert!(
        g.requirements
            .iter()
            .any(|r| r.value == "current authoritative DNS provider")
    );
    assert!(
        g.next_actions
            .iter()
            .any(|a| a.namespace == "cloudflare" && a.operation == "dns.audit")
    );
    let g = c.select("dns.records.apply", &Default::default()).unwrap();
    let v = serde_json::to_value(g).unwrap();
    assert!(
        v["next_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["operation"] == "dns.records.resolve.plan"
                && a["on"] == json!(["outcome_unknown"]))
    );
}
