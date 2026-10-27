use super::*;
use crate::transport::WriteTransport;
use serde_json::{Value, json};
struct Never;
impl ReadTransport for Never {
    fn get(&mut self, _: &str) -> Result<Value> {
        panic!("provider accessed")
    }
}
impl WriteTransport for Never {
    fn post(&mut self, _: &str, _: &Value) -> Result<Value> {
        panic!("write attempted")
    }
    fn put(&mut self, _: &str, _: &Value) -> Result<Value> {
        panic!("write attempted")
    }
}
impl RecordWriteTransport for Never {
    fn patch(&mut self, _: &str, _: &Value) -> Result<Value> {
        panic!("write attempted")
    }
    fn delete(&mut self, _: &str) -> Result<Value> {
        panic!("write attempted")
    }
}
fn issued(expires_at: u64, deadline: Instant) -> (Editor, String) {
    let scope = Scope {
        account: "1".repeat(32),
        zone: "2".repeat(32),
        domain: "example.test".into(),
    };
    let plan = RecordPlan {
        implementation_version: env!("CARGO_PKG_VERSION").into(),
        implementation_source_sha: None,
        scope: scope.clone(),
        before: Snapshot {
            zone: json!({}),
            records: vec![],
        },
        edit: Edit::Delete {
            record_id: "3".repeat(32),
        },
        created_at: 0,
        expires_at,
        nonce: "test".into(),
    };
    let hash = digest(&plan).unwrap();
    (
        Editor {
            scope,
            issued: Some(Issued {
                plan,
                hash: hash.clone(),
                deadline,
            }),
        },
        hash,
    )
}
#[test]
fn wall_clock_expiration_is_consumed_without_provider_access() {
    let (mut editor, hash) = issued(0, Instant::now() + Duration::from_secs(300));
    assert_eq!(
        editor.apply(&hash, &mut Never).unwrap_err().code,
        "expired_plan"
    );
    assert_eq!(
        editor.apply(&hash, &mut Never).unwrap_err().code,
        "unissued_or_consumed_plan"
    );
}
#[test]
fn monotonic_deadline_refuses_a_plan_even_if_wall_clock_would_allow_it() {
    let (mut editor, hash) = issued(u64::MAX, Instant::now());
    assert_eq!(
        editor.apply(&hash, &mut Never).unwrap_err().code,
        "expired_plan"
    );
}
#[test]
fn deserializers_refuse_unreviewed_fields_and_unknown_operations() {
    assert!(serde_json::from_value::<Scope>(json!({"account":"1".repeat(32),"zone":"2".repeat(32),"domain":"example.test","token":"synthetic"})).is_err());
    assert!(
        serde_json::from_value::<Edit>(
            json!({"action":"delete","record_id":"3".repeat(32),"force":true})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<Edit>(json!({"action":"delete_zone"})).is_err());
}

#[test]
fn historical_creation_reconciliation_requires_exact_acknowledgement_and_no_drift() {
    let (editor, _) = issued(300, Instant::now());
    let mut plan = editor.issued.unwrap().plan;
    let id = "4".repeat(32);
    plan.edit = Edit::Create {
        record: RecordData {
            kind: RecordType::TXT,
            name: "example.test".into(),
            content: "MS=synthetic".into(),
            ttl: 3600,
            proxied: false,
            priority: None,
        },
    };
    let target = json!({"id":id,"type":"TXT","name":"example.test","content":"MS=synthetic","ttl":3600,"proxied":false});
    let after = Snapshot {
        zone: plan.before.zone.clone(),
        records: vec![target.clone()],
    };
    // Old approval is never replayed; only the observed outcome is checked.
    assert!(verify_observed(&plan, &id, &after).is_ok());
    assert!(verify_observed(&plan, &"5".repeat(32), &after).is_err());
    let mut changed = after.clone();
    changed.records[0]["content"] = json!("wrong");
    assert!(verify_observed(&plan, &id, &changed).is_err());
    changed = after.clone();
    changed.records.push(json!({"id":"6".repeat(32)}));
    assert!(verify_observed(&plan, &id, &changed).is_err());
    changed = after.clone();
    changed.zone = json!({"id":"wrong"});
    assert!(verify_observed(&plan, &id, &changed).is_err());
    plan.before.records.push(target);
    assert!(verify_observed(&plan, &id, &after).is_err());
}

#[test]
fn historical_update_reconciliation_preserves_unrelated_records_and_metadata() {
    let (editor, _) = issued(300, Instant::now());
    let mut plan = editor.issued.unwrap().plan;
    let id = "4".repeat(32);
    let original = json!({"id":id,"type":"TXT","name":"example.test","content":"old","ttl":60,"proxied":false,"comment":"retain"});
    plan.before.records = vec![original.clone()];
    plan.edit = Edit::Update {
        record_id: id.clone(),
        record: RecordData {
            kind: RecordType::TXT,
            name: "example.test".into(),
            content: "new".into(),
            ttl: 3600,
            proxied: false,
            priority: None,
        },
    };
    let mut record = original;
    record["content"] = json!("new");
    record["ttl"] = json!(3600);
    let mut after = Snapshot {
        zone: plan.before.zone.clone(),
        records: vec![record],
    };
    assert!(verify_observed(&plan, &id, &after).is_ok());
    after.records[0]["comment"] = json!("removed");
    assert!(verify_observed(&plan, &id, &after).is_err());
    assert!(verify_observed(&plan, &"5".repeat(32), &after).is_err());
}
