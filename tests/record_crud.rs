mod record_support;
use record_support::*;
use zixcel_domain::record_editor::{Edit, ReceiptState, RecordType};
const TYPES: [RecordType; 5] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::TXT,
    RecordType::MX,
];
#[test]
fn all_five_types_create_and_verify_without_touching_other_records() {
    for kind in TYPES {
        let mut untouched = existing();
        untouched["id"] = "5".repeat(32).into();
        untouched["name"] = "other.example.test".into();
        let mut api = Api {
            records: vec![untouched.clone()],
            ..Default::default()
        };
        let mut editor = editor();
        let plan = editor
            .plan(Edit::Create { record: data(kind) }, &mut api)
            .unwrap();
        assert_eq!(api.writes, 0);
        let receipt = editor.apply(&plan.sha256, &mut api).unwrap();
        assert_eq!(receipt.state, ReceiptState::ProviderVerified);
        assert_eq!(receipt.writes_attempted, 1);
        assert_eq!(api.method, "POST");
        assert_eq!(api.records[0], untouched);
        assert_eq!(api.records[1]["type"], serde_json::to_value(kind).unwrap());
    }
}
#[test]
fn all_five_types_update_with_patch_and_preserve_metadata() {
    for kind in TYPES {
        let mut before = existing();
        for (k, v) in serde_json::to_value(data(kind))
            .unwrap()
            .as_object()
            .unwrap()
        {
            before[k] = v.clone();
        }
        let mut api = Api {
            records: vec![before],
            ..Default::default()
        };
        let mut editor = editor();
        let mut desired = data(kind);
        desired.content = match kind {
            RecordType::A => "192.0.2.8",
            RecordType::AAAA => "2001:db8::8",
            RecordType::CNAME | RecordType::MX => "other.example.test",
            RecordType::TXT => "verification=synthetic",
        }
        .into();
        let plan = editor
            .plan(
                Edit::Update {
                    record_id: RECORD.into(),
                    record: desired.clone(),
                },
                &mut api,
            )
            .unwrap();
        assert_eq!(
            editor.apply(&plan.sha256, &mut api).unwrap().state,
            ReceiptState::ProviderVerified
        );
        assert_eq!(api.method, "PATCH");
        assert_eq!(api.records[0]["content"], desired.content);
        assert_eq!(api.records[0]["comment"], "keep");
        assert_eq!(
            api.records[0]["tags"],
            serde_json::json!(["owner:synthetic"])
        );
        assert_eq!(
            api.records[0]["settings"],
            serde_json::json!({"ipv4_only":true})
        );
    }
}
