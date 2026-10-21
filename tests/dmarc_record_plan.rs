mod record_support;
use record_support::*;
use serde_json::json;
use zixcel_domain::record_editor::{Edit, RecordType};
fn desired() -> zixcel_domain::record_editor::RecordData {
    let mut row = data(RecordType::TXT);
    row.name = "_dmarc.example.test".into();
    row.content = "v=DMARC1; p=none; rua=mailto:reports@example.test".into();
    row
}
#[test]
fn invalid_or_second_policy_does_not_issue_a_plan_or_write() {
    let mut port = Api::default();
    let mut editor = editor();
    let mut record = desired();
    record.content = "v=DMARC1; p=allow".into();
    assert!(editor.plan(Edit::Create { record }, &mut port).is_err());
    let mut existing = serde_json::to_value(desired()).unwrap();
    existing["id"] = RECORD.into();
    port.records.push(existing);
    assert_eq!(
        editor
            .plan(Edit::Create { record: desired() }, &mut port)
            .unwrap_err()
            .code,
        "duplicate_record"
    );
    let mut row = desired();
    row.content = "v=DMARC1; p=reject".into();
    assert_eq!(
        editor
            .plan(Edit::Create { record: row }, &mut port)
            .unwrap_err()
            .code,
        "dmarc_consolidation_requires_explicit_review"
    );
    assert_eq!(port.writes, 0);
}
#[test]
fn explicit_repair_preserves_mail_and_requires_fresh_one_use_approval() {
    let mut malformed = serde_json::to_value(desired()).unwrap();
    malformed["id"] = RECORD.into();
    malformed["content"] = "v=DMARC1; p=broken".into();
    let mail = json!({"id":CREATED,"type":"MX","name":"example.test","content":"mail.example.test","ttl":3600,"proxied":false,"priority":10});
    let mut port = Api {
        records: vec![malformed, mail.clone()],
        ..Api::default()
    };
    let mut editor = editor();
    let plan = editor
        .plan(
            Edit::Update {
                record_id: RECORD.into(),
                record: desired(),
            },
            &mut port,
        )
        .unwrap();
    assert_eq!(port.writes, 0);
    assert!(plan.plan.before.records.contains(&mail));
    let receipt = editor.apply(&plan.sha256, &mut port).unwrap();
    assert_eq!(
        receipt.state,
        zixcel_domain::record_editor::ReceiptState::ProviderVerified
    );
    assert!(port.records.contains(&mail));
    assert!(editor.apply(&plan.sha256, &mut port).is_err());
    assert_eq!(port.writes, 1);
}
