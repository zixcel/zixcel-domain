use zixcel_domain::{dmarc, dns_name, domain_name};
#[test]
fn service_labels_are_valid_dns_owners_without_becoming_hostnames() {
    assert_eq!(
        dns_name::record_name("_DMARC.Example.org.").unwrap(),
        "_dmarc.example.org"
    );
    assert!(domain_name("_dmarc.example.org").is_err());
    for name in [
        "_dmarc..example.org",
        "_.example.org",
        "_dmarc.example.org/path",
        "_dmarc.local",
        "_bad_name.example.org",
    ] {
        assert!(dns_name::record_name(name).is_err(), "{name}");
    }
}
#[test]
fn quoted_chunks_join_only_within_the_same_record() {
    let p =
        dmarc::parse(&[r#""v=DMARC1;" " p=none; rua=mailto:reports@example.org""#.into()]).unwrap();
    assert_eq!(p.policy, "none");
    assert_eq!(p.percentage, 100);
    assert!(!p.sender_alignment_verified);
    assert!(!p.external_report_authorization_verified);
    assert_eq!(
        dmarc::parse(&["v=DMARC1; p=none".into(), "v=DMARC1; p=reject".into()])
            .unwrap_err()
            .code,
        "multiple_dmarc_records"
    );
    assert!(dmarc::parse(&["v=DMARC1;".into(), "p=none".into()]).is_err());
}
#[test]
fn invalid_policy_order_duplicates_percent_and_txt_escapes_are_rejected() {
    for text in [
        "v=DMARC1; p=allow",
        "v=DMARC1; p=none; p=reject",
        "p=none; v=DMARC1",
        "v=DMARC1; rua=mailto:r@example.org; p=none",
        "v=DMARC1; p=none; pct=101",
        "v=DMARC1; p=none; adkim=unknown",
        r#""v=DMARC1; p=none\999""#,
        r#""v=DMARC1; p=none" suffix"#,
    ] {
        assert!(dmarc::parse(&[text.into()]).is_err(), "{text}");
    }
}
#[test]
fn monitoring_and_existing_report_destinations_are_preserved_without_policy_escalation() {
    let p =
        dmarc::parse(&["v=DMARC1; p=none; pct=25; rua=mailto:r@example.net; x_future=kept".into()])
            .unwrap();
    assert_eq!(p.percentage, 25);
    assert_eq!(p.tags["rua"], "mailto:r@example.net");
    assert_eq!(p.tags["x_future"], "kept");
}
