use serde_json::json;
use zix_native_provider::{Request, validate_request};
#[test]
fn public_dns_command_cannot_receive_registrar_secrets_or_mutation_arguments() {
    let m = zixcel_domain_cli::manifest();
    m.validate().unwrap();
    let c = m.commands.iter().find(|c| c.id == "dns.audit").unwrap();
    assert!(
        c.environment
            .as_ref()
            .unwrap()
            .credential_environment
            .is_empty()
    );
    assert!(c.required_permissions.is_empty());
    assert_eq!(c.effect, "read");
    let mut r:Request=serde_json::from_value(json!({"schema":"zix-provider/v1","id":"0".repeat(32),
        "operation":"dns.audit","arguments":{"domain":"example.org"},"limits":{"timeout_ms":5000,"maximum_response_bytes":65536}})).unwrap();
    assert!(validate_request(&m, &r).is_ok());
    r.arguments
        .insert("url".into(), "https://other.invalid".into());
    assert!(zixcel_domain_cli::execute(&r).is_err());
}
