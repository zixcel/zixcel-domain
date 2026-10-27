use super::*;
use std::os::unix::fs::PermissionsExt;
#[test]
fn historical_plan_and_acknowledgement_must_match_private_journal() {
    let root = std::env::temp_dir().join(format!(
        "cf-recovery-{}-{}",
        std::process::id(),
        now().unwrap()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let profile = Profile {
        domain: "example.test".into(),
        target: Target::Cloudflare {
            account: "1".repeat(32),
            zone: "2".repeat(32),
        },
        journal_directory: root.to_str().unwrap().into(),
    };
    let p: RecordPlan = decode(json!({"implementation_version":"0.7.1","implementation_source_sha":null,"scope":{"domain":"example.test","account":"1".repeat(32),"zone":"2".repeat(32)},"before":{"zone":{},"records":[]},"edit":{"action":"create","record":{"type":"TXT","name":"example.test","content":"synthetic","ttl":3600,"proxied":false}},"created_at":1,"expires_at":301,"nonce":"synthetic"})).unwrap();
    let envelope = LocalPlan::new(
        "dns.records.apply".into(),
        Binding::for_catalog("zixcel-domain-cli", "0.3.2", &json!({}), &"a".repeat(64)),
        encoded(Payload {
            profile: profile.clone(),
            profile_sha256: "b".repeat(64),
            change: encoded(&p).unwrap(),
        })
        .unwrap(),
    );
    let path = root.join("original.json");
    std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (hash, old) = original(path.to_str().unwrap(), &profile, &"b".repeat(64)).unwrap();
    assert_eq!(hash, envelope.digest());
    assert!(original(path.to_str().unwrap(), &profile, &"c".repeat(64)).is_err());
    let mut receipt = json!({"status":"outcome_unknown","state":"outcome_unknown","writes_attempted":1,"blind_replay_allowed":false,"record_id":"3".repeat(32),"plan_sha256":zixcel_domain::domain_release::digest(&old).unwrap(),"error":{"code":"incomplete_inventory"}});
    Journal::open(&root)
        .unwrap()
        .admit(&hash, "example.test")
        .unwrap()
        .finish(&receipt.to_string(), false)
        .unwrap();
    assert_eq!(acknowledged(&profile, &hash, &old).unwrap(), "3".repeat(32));
    let receipt_path = root.join(format!("{hash}.receipt"));
    for (key, value) in [
        ("record_id", Value::Null),
        ("plan_sha256", json!("wrong")),
        ("blind_replay_allowed", json!(true)),
    ] {
        let previous = receipt[key].clone();
        receipt[key] = value;
        std::fs::write(&receipt_path, receipt.to_string()).unwrap();
        assert!(acknowledged(&profile, &hash, &old).is_err());
        receipt[key] = previous;
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(original(path.to_str().unwrap(), &profile, &"b".repeat(64)).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
