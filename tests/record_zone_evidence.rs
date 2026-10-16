mod record_support;
use record_support::*;
use zixcel_domain::record_editor::{Edit, ReceiptState, RecordType};
#[test]
fn zone_evidence_omits_unrelated_vendor_metadata_and_is_stable_across_its_changes() {
    let zone = serde_json::json!({"id":ZONE,"name":"example.test","status":"active",
        "account":{"id":ACCOUNT,"name":"PRIVATE_VENDOR_METADATA"},"modified_on":"before"});
    let mut api = Api {
        zone_override: Some(zone),
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
    assert!(
        !serde_json::to_string(&plan)
            .unwrap()
            .contains("PRIVATE_VENDOR_METADATA")
    );
    api.zone_override.as_mut().unwrap()["modified_on"] = "after".into();
    assert_eq!(
        editor.apply(&plan.sha256, &mut api).unwrap().state,
        ReceiptState::ProviderVerified
    );
}
