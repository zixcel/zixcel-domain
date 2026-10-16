mod record_support;
use record_support::*;
use serde_json::Value;
use zixcel_domain::record_editor::{Edit, ReceiptState, RecordType};
const TYPES: [RecordType; 5] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::TXT,
    RecordType::MX,
];
#[test]
fn all_five_types_delete_only_the_approved_id() {
    for kind in TYPES {
        let mut before = serde_json::to_value(data(kind)).unwrap();
        before["id"] = RECORD.into();
        let mut other = existing();
        other["id"] = "5".repeat(32).into();
        other["name"] = "other.example.test".into();
        let mut api = Api {
            records: vec![before, other.clone()],
            ..Default::default()
        };
        let mut editor = editor();
        let plan = editor
            .plan(
                Edit::Delete {
                    record_id: RECORD.into(),
                },
                &mut api,
            )
            .unwrap();
        assert_eq!(
            editor.apply(&plan.sha256, &mut api).unwrap().state,
            ReceiptState::ProviderVerified
        );
        assert_eq!(api.records, vec![other]);
        assert_eq!(api.method, "DELETE");
    }
}
#[test]
fn provider_inventory_order_and_pagination_do_not_change_the_plan() {
    let records: Vec<Value>=(10..71u128).map(|n| serde_json::json!({"id":format!("{n:032x}"),
        "name":format!("entry{n}.example.test"),"type":"TXT","content":"synthetic","ttl":3600,"proxied":false})).collect();
    let mut api = Api {
        records,
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
    api.records.reverse();
    assert_eq!(
        editor.apply(&plan.sha256, &mut api).unwrap().state,
        ReceiptState::ProviderVerified
    );
}
