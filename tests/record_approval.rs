mod record_support;
use record_support::*;
use zixcel_domain::record_editor::{Edit, ReceiptState, RecordType};
#[test]
fn unissued_or_cross_session_approval_never_reaches_a_write() {
    let mut api = Api::default();
    let mut first = editor();
    let mut second = editor();
    assert!(first.apply(&"0".repeat(64), &mut api).is_err());
    assert_eq!(api.reads, 0);
    let p = first
        .plan(
            Edit::Create {
                record: data(RecordType::A),
            },
            &mut api,
        )
        .unwrap();
    let q = second
        .plan(
            Edit::Create {
                record: data(RecordType::A),
            },
            &mut api,
        )
        .unwrap();
    assert_ne!(p.sha256, q.sha256);
    let reads = api.reads;
    assert!(second.apply(&p.sha256, &mut api).is_err());
    assert!(second.apply(&q.sha256, &mut api).is_err());
    assert_eq!(api.reads, reads);
    assert_eq!(api.writes, 0);
}
#[test]
fn changing_the_review_copy_cannot_change_the_issued_intent() {
    let mut api = Api::default();
    let mut editor = editor();
    let mut plan = editor
        .plan(
            Edit::Create {
                record: data(RecordType::A),
            },
            &mut api,
        )
        .unwrap();
    plan.plan.edit = Edit::Delete {
        record_id: RECORD.into(),
    };
    assert_eq!(
        editor.apply(&plan.sha256, &mut api).unwrap().state,
        ReceiptState::ProviderVerified
    );
    assert_eq!(api.method, "POST");
    assert_eq!(api.records[0]["content"], "192.0.2.7");
    let reads = api.reads;
    assert!(editor.apply(&plan.sha256, &mut api).is_err());
    assert_eq!(api.reads, reads);
    assert_eq!(api.writes, 1);
}
#[test]
fn drift_in_any_record_consumes_approval_before_writing() {
    let mut api = Api {
        records: vec![existing()],
        ..Default::default()
    };
    let mut editor = editor();
    let plan = editor.plan(change(), &mut api).unwrap();
    api.records[0]["comment"] = "edited elsewhere".into();
    assert_eq!(
        editor.apply(&plan.sha256, &mut api).unwrap_err().code,
        "snapshot_drift"
    );
    let reads = api.reads;
    assert!(editor.apply(&plan.sha256, &mut api).is_err());
    assert_eq!(api.reads, reads);
    assert_eq!(api.writes, 0);
}
