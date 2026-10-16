mod record_support;
use record_support::*;
use zixcel_domain::record_editor::{Edit, ReceiptState, RecordType};
#[test]
fn changed_account_is_rejected_again_at_apply_time() {
    let mut api = Api {
        records: vec![existing()],
        ..Default::default()
    };
    let mut editor = editor();
    let plan = editor.plan(change(), &mut api).unwrap();
    api.wrong_scope = true;
    assert_eq!(
        editor.apply(&plan.sha256, &mut api).unwrap_err().code,
        "wrong_zone_scope"
    );
    assert_eq!(api.writes, 0);
}
#[test]
fn unknown_outcome_is_not_retried_even_when_the_server_applied_it() {
    let mut api = Api {
        lost_response: true,
        ..Default::default()
    };
    let mut editor = editor();
    let plan = editor
        .plan(
            Edit::Create {
                record: data(RecordType::A),
            },
            &mut api,
        )
        .unwrap();
    let receipt = editor.apply(&plan.sha256, &mut api).unwrap();
    assert_eq!(receipt.state, ReceiptState::OutcomeUnknown);
    assert_eq!(receipt.writes_attempted, 1);
    assert!(!receipt.blind_replay_allowed);
    assert_eq!(api.records.len(), 1);
    assert!(editor.apply(&plan.sha256, &mut api).is_err());
    assert_eq!(api.writes, 1);
    assert_eq!(
        editor
            .plan(
                Edit::Create {
                    record: data(RecordType::A)
                },
                &mut api
            )
            .unwrap_err()
            .code,
        "duplicate_record"
    );
}
#[test]
fn issuing_a_new_plan_invalidates_the_previous_approval() {
    let mut api = Api::default();
    let mut editor = editor();
    let first = editor
        .plan(
            Edit::Create {
                record: data(RecordType::A),
            },
            &mut api,
        )
        .unwrap();
    let second = editor
        .plan(
            Edit::Create {
                record: data(RecordType::AAAA),
            },
            &mut api,
        )
        .unwrap();
    assert_ne!(first.sha256, second.sha256);
    assert!(editor.apply(&first.sha256, &mut api).is_err());
    assert_eq!(api.writes, 0);
}
