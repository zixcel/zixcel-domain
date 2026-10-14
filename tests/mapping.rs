use serde_json::json;
use zixcel_domain::mapping::{MappingInput, preview};

fn input() -> MappingInput {
    serde_json::from_value(json!({
        "cloudflare_account_id":"00000000000000000000000000000001",
        "bindings":[{"organization":"example-org","domain":"example.test","cloudflare_account_id":"00000000000000000000000000000001"}],
        "registrar_domains":[{"domain":"example.test","expiration":null}],
        "cloudflare_zones":[]
    })).unwrap()
}

#[test]
fn invisible_zone_is_never_automatic_creation_authorization() {
    let result = preview(&input()).unwrap();
    assert_eq!(
        result.rows[0].next_step,
        "verify_zone_visibility_before_creation_review"
    );
    assert!(!result.write_authorized);
    assert!(result.rows[0].registrar_visible);
    assert!(result.unassigned_registrar_domains.is_empty());
}

#[test]
fn wrong_account_and_duplicate_imported_domains_fail() {
    let mut wrong = input();
    wrong.bindings[0].cloudflare_account_id = "00000000000000000000000000000000".into();
    assert_eq!(preview(&wrong).unwrap_err().code, "wrong_account");
    let mut duplicate = input();
    duplicate
        .registrar_domains
        .push(zixcel_domain::valuedomain::Domain {
            domain: "EXAMPLE.test.".into(),
            expiration: None,
        });
    assert_eq!(preview(&duplicate).unwrap_err().code, "duplicate_domain");
}

#[test]
fn unknown_registrar_domain_requires_explicit_assignment() {
    let mut input = input();
    input
        .registrar_domains
        .push(zixcel_domain::valuedomain::Domain {
            domain: "unassigned.test".into(),
            expiration: None,
        });
    let result = preview(&input).unwrap();
    assert_eq!(result.unassigned_registrar_domains, vec!["unassigned.test"]);
}
