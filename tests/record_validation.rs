mod record_support;
use record_support::*;
use zixcel_domain::record_editor::{Edit, Editor, RecordType, Scope};
#[test]
fn invalid_inputs_are_refused_before_any_provider_access() {
    let base = data(RecordType::A);
    let mut invalid = Vec::new();
    for name in [
        "notexample.test",
        "example.test.evil.test",
        "a.*.example.test",
        "app.other.test",
        " app.example.test",
    ] {
        let mut r = base.clone();
        r.name = name.into();
        invalid.push(r);
    }
    for ttl in [0, 2, 59, 86401] {
        let mut r = base.clone();
        r.ttl = ttl;
        invalid.push(r);
    }
    for content in ["PRIVATE_CANARY", "::1", "192.0.2.1\n"] {
        let mut r = base.clone();
        r.content = content.into();
        invalid.push(r);
    }
    let mut r = data(RecordType::AAAA);
    r.content = "192.0.2.7".into();
    invalid.push(r);
    let mut r = data(RecordType::CNAME);
    r.content = r.name.clone();
    invalid.push(r);
    let mut r = data(RecordType::TXT);
    r.proxied = true;
    r.ttl = 1;
    invalid.push(r);
    let mut r = base.clone();
    r.proxied = true;
    invalid.push(r);
    let mut r = base.clone();
    r.priority = Some(10);
    invalid.push(r);
    let mut r = data(RecordType::MX);
    r.priority = None;
    invalid.push(r);
    for content in [String::new(), "x".repeat(2049), "value\ncontinued".into()] {
        let mut r = data(RecordType::TXT);
        r.content = content;
        invalid.push(r);
    }
    for record in invalid {
        let mut api = Api::default();
        let error = editor()
            .plan(Edit::Create { record }, &mut api)
            .unwrap_err();
        assert!(!error.to_string().contains("PRIVATE_CANARY"));
        assert_eq!(api.reads, 0);
        assert_eq!(api.writes, 0);
    }
}
#[test]
fn invalid_scope_ids_and_record_path_injection_are_refused() {
    assert!(
        Editor::new(Scope {
            account: "../account".into(),
            zone: ZONE.into(),
            domain: "example.test".into()
        })
        .is_err()
    );
    assert!(
        Editor::new(Scope {
            account: ACCOUNT.into(),
            zone: ZONE.into(),
            domain: "localhost".into()
        })
        .is_err()
    );
    let mut api = Api::default();
    assert!(
        editor()
            .plan(
                Edit::Delete {
                    record_id: "../records".into()
                },
                &mut api
            )
            .is_err()
    );
    assert_eq!(api.reads, 0);
}
#[test]
fn fqdn_ip_and_target_normalization_is_reviewed_before_approval() {
    let mut r = data(RecordType::AAAA);
    r.name = "APP.EXAMPLE.TEST.".into();
    r.content = "2001:0db8:0:0:0:0:0:7".into();
    let mut api = Api::default();
    let plan = editor().plan(Edit::Create { record: r }, &mut api).unwrap();
    if let Edit::Create { record } = plan.plan.edit {
        assert_eq!(record.name, "app.example.test");
        assert_eq!(record.content, "2001:db8::7");
    } else {
        panic!("wrong intent")
    }
}
