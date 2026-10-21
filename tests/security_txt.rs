use zixcel_domain::security_txt::inspect;
#[test]
fn valid_fields_are_not_a_signature_or_delivery_acceptance() {
    let report=inspect("Contact: https://example.org/security\nExpires: 2030-01-01T00:00:00Z\nCanonical: https://example.org/.well-known/security.txt\n", "example.org",1_700_000_000).unwrap();
    assert_eq!(report["signature_verified"], false);
    assert_eq!(report["contact_delivery_verified"], false);
    assert_eq!(report["authorization_to_test_granted"], false);
}
#[test]
fn missing_expired_duplicate_unsafe_and_wrong_canonical_fields_are_rejected() {
    for text in [
        "Contact: mailto:security@example.org",
        "Expires: 2030-01-01T00:00:00Z",
        "Contact: http://example.org\nExpires: 2030-01-01T00:00:00Z",
        "Contact: mailto:security@example.org\nExpires: 2000-01-01T00:00:00Z",
        "Contact: mailto:security@example.org\nExpires: 2030-01-01T00:00:00Z\nExpires: 2031-01-01T00:00:00Z",
        "Contact: mailto:security@example.org\nExpires: 2030-01-01T00:00:00Z\nCanonical: https://wrong.org/.well-known/security.txt",
    ] {
        assert!(inspect(text, "example.org", 1_700_000_000).is_err());
    }
    assert!(inspect(&"x".repeat(32769), "example.org", 1_700_000_000).is_err());
}
