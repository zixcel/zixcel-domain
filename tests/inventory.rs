use serde_json::{Value, json};
use std::collections::VecDeque;
use zixcel_domain::{
    Error, Result, cloudflare, domain_name, transport::ReadTransport, valuedomain,
};

struct Fixture {
    responses: VecDeque<(&'static str, Result<Value>)>,
}
impl ReadTransport for Fixture {
    fn get(&mut self, path: &str) -> Result<Value> {
        let (expected, response) = self.responses.pop_front().expect("unexpected request");
        assert_eq!(path, expected);
        response
    }
}
fn fixture(responses: Vec<(&'static str, Result<Value>)>) -> Fixture {
    Fixture {
        responses: responses.into(),
    }
}
fn vd_page(page: u64, max: u64, results: Vec<Value>) -> Value {
    json!({"paging":{"page":page,"max":max,"limit":50},"results":results})
}

#[test]
fn canonicalization_rejects_url_injection() {
    assert_eq!(
        domain_name("例え.テスト.").unwrap(),
        "xn--r8jz45g.xn--zckzah"
    );
    for invalid in [
        "example.org?token=secret",
        "../example.org",
        "a.example/x",
        "-x.org",
        "x..org",
        "localhost",
    ] {
        assert_eq!(domain_name(invalid).unwrap_err().code, "invalid_domain");
    }
}

#[test]
fn value_domain_inventory_collects_all_pages_and_projects_safe_fields() {
    let first: Vec<Value> = (0..50)
        .map(|n| json!({"domainname":format!("domain{n}.test"), "ignored_personal_data":"private"}))
        .collect();
    let mut transport = fixture(vec![
        ("/domains?limit=50&page=1", Ok(vd_page(1, 51, first))),
        (
            "/domains?limit=50&page=2",
            Ok(vd_page(2, 51, vec![json!({"domainname":"last.test"})])),
        ),
    ]);
    let inventory = valuedomain::domains(&mut transport).unwrap();
    assert_eq!(inventory.len(), 51);
    assert!(
        !serde_json::to_string(&inventory)
            .unwrap()
            .contains("private")
    );
    assert!(transport.responses.is_empty());
}

#[test]
fn partial_inventory_never_becomes_success() {
    let first = (0..50)
        .map(|n| json!({"domainname":format!("domain{n}.test")}))
        .collect();
    let mut transport = fixture(vec![
        ("/domains?limit=50&page=1", Ok(vd_page(1, 51, first))),
        ("/domains?limit=50&page=2", Err(Error::new("forbidden"))),
    ]);
    assert_eq!(
        valuedomain::domains(&mut transport).unwrap_err().code,
        "forbidden"
    );
}

#[test]
fn short_and_duplicate_pages_are_rejected() {
    let mut short = fixture(vec![(
        "/domains?limit=50&page=1",
        Ok(vd_page(1, 2, vec![json!({"domainname":"one.test"})])),
    )]);
    assert_eq!(
        valuedomain::domains(&mut short).unwrap_err().code,
        "incomplete_inventory"
    );
    let mut duplicate = fixture(vec![(
        "/domains?limit=50&page=1",
        Ok(vd_page(
            1,
            2,
            vec![
                json!({"domainname":"one.test"}),
                json!({"domainname":"ONE.test."}),
            ],
        )),
    )]);
    assert_eq!(
        valuedomain::domains(&mut duplicate).unwrap_err().code,
        "duplicate_domain"
    );
}

#[test]
fn registrar_dns_is_preserved_but_not_claimed_authoritative() {
    let records = "mx @ 10\ntxt @ v=spf1 -all\nunknown opaque fields";
    let mut transport = fixture(vec![
        (
            "/domains/example.test/nameserver",
            Ok(
                json!({"results":{"domainname":"example.test","ns":["alice.ns.cloudflare.com","bob.ns.cloudflare.com"]}}),
            ),
        ),
        (
            "/domains/example.test/dns",
            Ok(
                json!({"results":{"domainname":"example.test","records":records,"ttl":1200,"ns_type":"valuedomain1"}}),
            ),
        ),
    ]);
    let settings = valuedomain::settings(&mut transport, "example.test").unwrap();
    assert!(!settings.authority_verified);
    assert_eq!(settings.stored_dns_records, records);
}

#[test]
fn cloudflare_wrong_account_and_partial_success_are_rejected() {
    const ACCOUNT: &str = "00000000000000000000000000000001";
    const PATH: &str = "/zones?account.id=00000000000000000000000000000001&per_page=50&page=1";
    let zone = json!({"id":"00000000000000000000000000000001","account":{"id":"wrong"},"name":"example.test","name_servers":[],"status":"active"});
    let mut wrong = fixture(vec![(
        PATH,
        Ok(json!({"success":true,"result_info":{"page":1,"total_count":1},"result":[zone]})),
    )]);
    assert_eq!(
        cloudflare::zones(&mut wrong, ACCOUNT).unwrap_err().code,
        "wrong_account"
    );
    let mut failed = fixture(vec![(PATH, Ok(json!({"success":false,"result":[]})))]);
    assert_eq!(
        cloudflare::zones(&mut failed, ACCOUNT).unwrap_err().code,
        "provider_failed"
    );
}

#[test]
fn cloudflare_records_preserve_mail_and_vendor_extensions() {
    let record = json!({"id":"00000000000000000000000000000001","type":"MX","name":"example.test","priority":10,"content":"mail.example.test","settings":{"future_field":true},"comment":"existing owner"});
    let mut transport = fixture(vec![(
        "/zones/00000000000000000000000000000002/dns_records?order=name&per_page=50&page=1",
        Ok(
            json!({"success":true,"result_info":{"page":1,"total_count":1},"result":[record.clone()]}),
        ),
    )]);
    assert_eq!(
        cloudflare::records(&mut transport, "00000000000000000000000000000002").unwrap(),
        vec![record]
    );
}

#[test]
fn binding_ownership_is_explicit_and_duplicate_names_fail() {
    let mut bindings: Vec<zixcel_domain::DomainBinding> = serde_json::from_value(json!([
        {"organization":"zixcel","domain":"example.test","cloudflare_account_id":"00000000000000000000000000000001"}
    ])).unwrap();
    zixcel_domain::validate_bindings(&bindings).unwrap();
    bindings.push(bindings[0].clone());
    bindings[1].organization = "other".into();
    assert_eq!(
        zixcel_domain::validate_bindings(&bindings)
            .unwrap_err()
            .code,
        "duplicate_domain"
    );
}

#[test]
fn recursive_ns_observation_does_not_claim_authoritative_acceptance() {
    let mut transport = fixture(vec![(
        "/dns-query?name=example.test&type=NS",
        Ok(json!({
            "Status":0,"TC":false,"AD":true,
            "Question":[{"name":"example.test.","type":2}],
            "Answer":[{"name":"example.test.","type":2,"data":"alice.ns.cloudflare.com."}]
        })),
    )]);
    let observation =
        zixcel_domain::inspection::public_nameservers(&mut transport, "example.test").unwrap();
    assert_eq!(observation.observation, "recursive_resolver");
    assert_eq!(observation.nameservers, vec!["alice.ns.cloudflare.com"]);
    assert!(observation.dnssec_validated);
}

#[test]
fn wrong_dns_question_and_truncated_answers_fail_closed() {
    for response in [
        json!({"Status":0,"TC":false,"Question":[{"name":"other.test.","type":2}],"Answer":[]}),
        json!({"Status":0,"TC":true,"Question":[{"name":"example.test.","type":2}],"Answer":[]}),
    ] {
        let mut transport = fixture(vec![("/dns-query?name=example.test&type=NS", Ok(response))]);
        assert!(
            zixcel_domain::inspection::public_nameservers(&mut transport, "example.test").is_err()
        );
    }
}

#[test]
fn inspection_preserves_ns_but_blocks_dns_plan_after_dns_auth_failure() {
    let mut registrar = fixture(vec![
        (
            "/domains?limit=50&page=1",
            Ok(vd_page(1, 1, vec![json!({"domainname":"example.test"})])),
        ),
        (
            "/domains/example.test/nameserver",
            Ok(json!({"results":{"domainname":"example.test","ns":["ns1.value-domain.com"]}})),
        ),
        (
            "/domains/example.test/dns",
            Err(Error::new("unauthorized").with_context("valuedomain-v2", "http_get")),
        ),
    ]);
    let mut dns = fixture(vec![(
        "/zones?account.id=00000000000000000000000000000001&per_page=50&page=1",
        Ok(json!({"success":true,"result_info":{"page":1,"total_count":0},"result":[]})),
    )]);
    let result = zixcel_domain::inspection::inspect(
        &mut registrar,
        &mut dns,
        "00000000000000000000000000000001",
    )
    .unwrap();
    assert!(!result.complete_for_dns_plan);
    assert!(!result.writes_performed);
    let value = serde_json::to_value(result).unwrap();
    assert_eq!(
        value["registrar_settings"][0]["nameservers"]["status"],
        "available"
    );
    assert_eq!(
        value["registrar_settings"][0]["stored_dns"]["status"],
        "unavailable"
    );
    assert_eq!(
        value["registrar_settings"][0]["stored_dns"]["error"]["provider"],
        "valuedomain-v2"
    );
    assert_eq!(
        value["registrar_settings"][0]["stored_dns"]["error"]["operation"],
        "read_stored_dns"
    );
}

#[test]
fn mixed_nameservers_and_lookalike_vendor_suffixes_are_not_trusted() {
    use zixcel_domain::inspection::configured_dns;
    assert_eq!(
        configured_dns(
            &["ns1.value-domain.com".into(), "ns1.contabo.net".into()],
            None
        )
        .unwrap(),
        "mixed_nameservers"
    );
    assert_eq!(
        configured_dns(&["ns1.value-domain.com.attacker.test".into()], None).unwrap(),
        "external_unverified"
    );
    let assigned = vec![
        "alice.ns.cloudflare.com".into(),
        "bob.ns.cloudflare.com".into(),
    ];
    assert_eq!(
        configured_dns(&assigned, Some(&assigned)).unwrap(),
        "cloudflare_assignment_matches"
    );
    assert!(configured_dns(&[], None).is_err());
}

#[test]
fn assigned_cloudflare_dns_does_not_request_unused_registrar_storage() {
    let ns = json!(["alice.ns.cloudflare.com", "bob.ns.cloudflare.com"]);
    let mut registrar = fixture(vec![
        (
            "/domains?limit=50&page=1",
            Ok(vd_page(1, 1, vec![json!({"domainname":"example.test"})])),
        ),
        (
            "/domains/example.test/nameserver",
            Ok(json!({"results":{"domainname":"example.test","ns":ns}})),
        ),
    ]);
    let mut dns = fixture(vec![
        (
            "/zones?account.id=00000000000000000000000000000001&per_page=50&page=1",
            Ok(json!({
                "success":true,"result_info":{"page":1,"total_count":1},"result":[{
                    "id":"00000000000000000000000000000002","account":{"id":"00000000000000000000000000000001"},
                    "name":"example.test","status":"active","name_servers":ns
                }]
            })),
        ),
        (
            "/zones/00000000000000000000000000000002/dns_records?order=name&per_page=50&page=1",
            Ok(json!({
                "success":true,"result_info":{"page":1,"total_count":0},"result":[]
            })),
        ),
    ]);
    let result = zixcel_domain::inspection::inspect(
        &mut registrar,
        &mut dns,
        "00000000000000000000000000000001",
    )
    .unwrap();
    assert!(result.complete_for_dns_plan);
    assert!(registrar.responses.is_empty());
    assert!(dns.responses.is_empty());
    let value = serde_json::to_value(result).unwrap();
    assert_eq!(
        value["registrar_settings"][0]["stored_dns"]["status"],
        "not_applicable"
    );
    assert_eq!(
        value["registrar_settings"][0]["stored_dns"]["reason"],
        "dns_hosted_on_cloudflare"
    );
}
