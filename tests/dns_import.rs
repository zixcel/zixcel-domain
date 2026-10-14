use zixcel_domain::dns_import::parse;

#[test]
fn mail_records_txt_payload_and_srv_parameters_are_preserved() {
    let records=parse("example.test",60,"mx mx1.mail.test. 10\nmx mx2.mail.test. 20\ntxt @ \"v=spf1 include:mail.test ~all\"\ntxt selector._domainkey \"v=DKIM1; p=public-fixture-key\"\nsrv _caldavs._tcp 0 5 443 box.example.test.").unwrap();
    assert_eq!(records.len(), 5);
    assert_eq!(records[0].name, "example.test");
    assert_eq!(records[0].priority, Some(10));
    assert_eq!(records[1].priority, Some(20));
    assert_eq!(
        records[2].content.as_deref(),
        Some("\"v=spf1 include:mail.test ~all\"")
    );
    assert_eq!(records[3].name, "selector._domainkey.example.test");
    let srv = records[4].data.as_ref().unwrap();
    assert_eq!((srv.priority, srv.weight, srv.port), (0, 5, 443));
    assert!(
        records
            .iter()
            .all(|record| !record.proxied && record.ttl == 60)
    );
}

#[test]
fn implicit_apex_txt_and_null_mx_are_not_dropped() {
    let records = parse("example.test", 3600, "txt \"v=spf1 mx -all\"\nmx . 0").unwrap();
    assert_eq!(records[0].name, "example.test");
    assert_eq!(records[1].content.as_deref(), Some("."));
    assert!(parse("example.test", 3600, "mx . 10").is_err());
}

#[test]
fn unknown_directives_and_malformed_quotes_reject_whole_import() {
    for text in [
        "a @ 192.0.2.1\nunknown @ opaque",
        "txt @ \"",
        "txt @ unquoted",
        "txt @ \"a\" \"b\"",
    ] {
        assert!(parse("example.test", 3600, text).is_err());
    }
}

#[test]
fn outside_zone_invalid_addresses_and_unapproved_ttl_are_rejected() {
    for text in [
        "a other.test. 192.0.2.1",
        "a @ not-an-ip",
        "a ../path 192.0.2.1",
        "srv _svc._tcp 0 0 70000 box.example.test.",
    ] {
        assert!(parse("example.test", 3600, text).is_err());
    }
    assert!(parse("example.test", 30, "a @ 192.0.2.1").is_err());
}

#[test]
fn wildcard_and_ipv6_are_dns_only_and_mx_subdomain_is_explicit() {
    let records = parse(
        "example.test",
        3600,
        "a * 192.0.2.1\naaaa @ 2001:db8::1\nmx mail.example.test. 10 box",
    )
    .unwrap();
    assert_eq!(records[0].name, "*.example.test");
    assert_eq!(records[1].content.as_deref(), Some("2001:db8::1"));
    assert_eq!(records[2].name, "box.example.test");
}
