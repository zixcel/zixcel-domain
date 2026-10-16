mod record_support;
use record_support::*;
use zixcel_domain::{record_cli, record_editor::Scope};
fn scope() -> Scope {
    Scope {
        account: ACCOUNT.into(),
        zone: ZONE.into(),
        domain: "example.test".into(),
    }
}
#[test]
fn invalid_wire_is_bounded_redacted_and_never_contacts_provider() {
    for input in [
        b"secret-invalid".to_vec(),
        vec![b'x'; 8193],
        b"{\"protocol\":2,\"command\":{\"action\":\"status\"}}\n".to_vec(),
        b"{\"protocol\":1,\"command\":{\"action\":\"status\",\"token\":\"secret\"}}\n".to_vec(),
        b"{\"protocol\":1,\"command\":{\"action\":\"delete_zone\"}}\n".to_vec(),
        b"{\"protocol\":1,\"command\":{\"action\":\"status\"},\"scope\":{}}\n".to_vec(),
        vec![0xff, b'\n'],
    ] {
        let mut api = Api::default();
        let mut output = Vec::new();
        assert!(
            record_cli::serve(scope(), std::io::Cursor::new(input), &mut output, &mut api).is_err()
        );
        assert!(output.is_empty());
        assert_eq!((api.reads, api.writes), (0, 0));
    }
}
#[test]
fn request_count_is_bounded_and_status_is_read_only() {
    let input = b"{\"protocol\":1,\"command\":{\"action\":\"status\"}}\n".repeat(101);
    let mut api = Api::default();
    let mut output = Vec::new();
    assert_eq!(
        record_cli::serve(scope(), std::io::Cursor::new(input), &mut output, &mut api)
            .unwrap_err()
            .code,
        "record_session_request_limit"
    );
    assert_eq!(output.iter().filter(|&&b| b == b'\n').count(), 100);
    assert_eq!((api.reads, api.writes), (0, 0));
}
#[test]
fn live_cli_validates_scope_before_credentials_and_advertises_only_implemented_types() {
    let binary = env!("CARGO_BIN_EXE_zixcel-domain");
    let bad = std::process::Command::new(binary)
        .args(["record-session", "invalid", ZONE, "example.test"])
        .env_remove("CLOUDFLARE_API_TOKEN")
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(bad.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bad.stdout).unwrap()["error"]["code"],
        "invalid_scope"
    );
    let caps = std::process::Command::new(binary)
        .arg("capabilities")
        .output()
        .unwrap();
    assert!(caps.status.success());
    let caps: serde_json::Value = serde_json::from_slice(&caps.stdout).unwrap();
    assert_eq!(
        caps["result"]["record_session"]["record_types"],
        serde_json::json!(["A", "AAAA", "CNAME", "TXT", "MX"])
    );
    assert_eq!(caps["result"]["token_permissions_verified"], false);
}
