mod record_support;
use record_support::*;
use zixcel_domain::record_editor::{self, Edit, ReceiptState, RecordPlan, RecordType};
#[test]
fn serialized_native_plan_reuses_validation_and_preserves_other_records() {
    let mut api = Api {
        records: vec![existing()],
        ..Default::default()
    };
    let p = editor().plan(change(), &mut api).unwrap().plan;
    let p: RecordPlan = serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
    assert_eq!(
        record_editor::apply_reviewed(&p, &mut api).unwrap().state,
        ReceiptState::ProviderVerified
    );
    assert_eq!(api.records[0]["comment"], "keep");
    assert!(record_editor::apply_reviewed(&p, &mut api).is_err());
    assert_eq!(api.writes, 1);
}
#[test]
fn expired_wrong_scope_and_drift_detached_plans_never_write() {
    let mut api = Api::default();
    let mut p = editor()
        .plan(
            Edit::Create {
                record: data(RecordType::TXT),
            },
            &mut api,
        )
        .unwrap()
        .plan;
    p.expires_at = 0;
    let reads = api.reads;
    assert!(record_editor::apply_reviewed(&p, &mut api).is_err());
    assert_eq!(api.reads, reads);
    let mut p = editor()
        .plan(
            Edit::Create {
                record: data(RecordType::TXT),
            },
            &mut api,
        )
        .unwrap()
        .plan;
    p.scope.account = "a".repeat(32);
    assert!(record_editor::apply_reviewed(&p, &mut api).is_err());
    assert_eq!(api.writes, 0);
}
