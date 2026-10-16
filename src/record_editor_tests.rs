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
