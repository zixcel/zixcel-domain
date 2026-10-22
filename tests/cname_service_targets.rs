mod record_support;
use record_support::*;
use zixcel_domain::record_editor::{Edit, ReceiptState, RecordType};
use zixcel_domain::{dns_import, dns_name, domain_name};

#[test]
fn dkim_cname_target_survives_plan_apply_and_import() {
    let target = "SELECTOR1._DOMAINKEY.MAIL.EXAMPLE.TEST.";
    let canonical = "selector1._domainkey.mail.example.test";
    let mut record = data(RecordType::CNAME);
    record.name = "selector1._domainkey.example.test".into();
    record.content = target.into();
    let mut api = Api::default();
    let mut editor = editor();
    let planned = editor.plan(Edit::Create { record }, &mut api).unwrap();
    let Edit::Create { record } = &planned.plan.edit else {
        panic!("wrong edit")
    };
    assert_eq!(record.content, canonical);
    let receipt = editor.apply(&planned.sha256, &mut api).unwrap();
    assert_eq!(receipt.state, ReceiptState::ProviderVerified);
    assert_eq!(api.writes, 1);
    let imported = dns_import::parse(
        "example.test",
        3600,
        &format!("cname selector1._domainkey {target}"),
    )
    .unwrap();
    assert_eq!(imported[0].content.as_deref(), Some(canonical));
    assert_eq!(dns_name::record_name(target).unwrap(), canonical);
}

#[test]
fn accepting_dns_service_names_does_not_relax_host_or_mx_validation() {
    assert_eq!(
        dns_name::record_name("_DMARC.BÜCHER.EXAMPLE.").unwrap(),
        "_dmarc.xn--bcher-kva.example"
    );
    let target = "selector1._domainkey.mail.example.test";
    assert!(domain_name(target).is_err());
    let mut mx = data(RecordType::MX);
    mx.content = target.into();
    let mut api = Api::default();
    assert!(
        editor()
            .plan(Edit::Create { record: mx }, &mut api)
            .is_err()
    );
    assert_eq!(api.reads, 0);
    assert_eq!(api.writes, 0);
    assert!(dns_import::parse("example.test", 3600, &format!("mx {target} 0")).is_err());
}

#[test]
fn service_targets_reject_url_wildcard_control_and_label_overflow_before_io() {
    for target in [
        "https://selector._domainkey.example.test",
        "selector._domainkey.example.test/path",
        "selector._domainkey.example.test?query",
        "user@selector._domainkey.example.test",
        "*._domainkey.example.test",
        "selector.._domainkey.example.test",
        "selector._domainkey.example.test:443",
        "selector._domainkey.example.test\n",
        "-selector._domainkey.example.test",
        "selector._domainkey-.example.test",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([
        format!("{}._domainkey.example.test", "a".repeat(64)),
        format!(
            "{}.{}.{}.{}._domainkey.example.test",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        ),
    ]) {
        let mut record = data(RecordType::CNAME);
        record.content = target.clone();
        let mut api = Api::default();
        assert!(editor().plan(Edit::Create { record }, &mut api).is_err());
        assert!(dns_name::record_name(&target).is_err());
        assert_eq!(api.reads, 0);
        assert_eq!(api.writes, 0);
    }
}
