mod record_support;
use record_support::*;
use zixcel_domain::record_editor::ReceiptState;
#[test]
fn metadata_loss_and_collateral_changes_are_not_accepted() {
    for collateral in [false, true] {
        let mut other = existing();
        other["id"] = "5".repeat(32).into();
        other["name"] = "other.example.test".into();
        let mut api = Api {
            records: vec![existing(), other],
            collateral,
            lose_metadata: !collateral,
            ..Default::default()
        };
        let mut editor = editor();
        let plan = editor.plan(change(), &mut api).unwrap();
        let receipt = editor.apply(&plan.sha256, &mut api).unwrap();
        assert_eq!(receipt.state, ReceiptState::OutcomeUnknown);
        assert_eq!(api.writes, 1);
        assert!(editor.apply(&plan.sha256, &mut api).is_err());
        assert_eq!(api.writes, 1);
    }
}
#[test]
fn failed_readback_never_turns_a_write_response_into_verified_success() {
    let mut api = Api {
        records: vec![existing()],
        fail_readback: true,
        ..Default::default()
    };
    let mut editor = editor();
    let plan = editor.plan(change(), &mut api).unwrap();
    let receipt = editor.apply(&plan.sha256, &mut api).unwrap();
    assert_eq!(receipt.state, ReceiptState::OutcomeUnknown);
    assert_eq!(api.records[0]["content"], "192.0.2.8");
}
#[test]
fn successful_response_with_unchanged_state_is_rejected() {
    let mut api = Api {
        records: vec![existing()],
        ignore_write: true,
        ..Default::default()
    };
    let mut editor = editor();
    let plan = editor.plan(change(), &mut api).unwrap();
    let receipt = editor.apply(&plan.sha256, &mut api).unwrap();
    assert_eq!(receipt.state, ReceiptState::OutcomeUnknown);
    assert_eq!(receipt.error.unwrap().code, "readback_mismatch");
}
#[test]
fn failed_request_is_attempted_only_once_and_receipt_does_not_expose_record_contents() {
    let mut api = Api {
        records: vec![existing()],
        fail_write: true,
        ..Default::default()
    };
    let mut editor = editor();
    let plan = editor.plan(change(), &mut api).unwrap();
    let receipt = editor.apply(&plan.sha256, &mut api).unwrap();
    let text = serde_json::to_string(&receipt).unwrap();
    assert_eq!(receipt.state, ReceiptState::OutcomeUnknown);
    assert_eq!(api.writes, 1);
    assert!(!text.contains("192.0.2."));
    assert!(!text.contains("owner:synthetic"));
    assert!(editor.apply(&plan.sha256, &mut api).is_err());
    assert_eq!(api.writes, 1);
}
