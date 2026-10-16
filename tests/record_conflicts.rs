mod record_support;
use record_support::*;
use zixcel_domain::record_editor::{Edit, RecordType};
#[test]
fn cname_conflicts_duplicates_and_missing_ids_are_rejected() {
    let mut api = Api {
        records: vec![existing()],
        ..Default::default()
    };
    for (kind, code) in [
        (RecordType::CNAME, "record_name_conflict"),
        (RecordType::A, "duplicate_record"),
    ] {
        assert_eq!(
            editor()
                .plan(Edit::Create { record: data(kind) }, &mut api)
                .unwrap_err()
                .code,
            code
        );
    }
    api.records[0]["type"] = "CNAME".into();
    assert_eq!(
        editor()
            .plan(
                Edit::Create {
                    record: data(RecordType::TXT)
                },
                &mut api
            )
            .unwrap_err()
            .code,
        "record_name_conflict"
    );
    assert_eq!(
        editor()
            .plan(
                Edit::Delete {
                    record_id: "9".repeat(32)
                },
                &mut api
            )
            .unwrap_err()
            .code,
        "record_missing"
    );
    assert_eq!(api.writes, 0);
}
#[test]
fn duplicate_provider_ids_and_oversized_snapshots_fail_closed() {
    let mut api = Api {
        records: vec![existing(), existing()],
        ..Default::default()
    };
    assert!(editor().plan(change(), &mut api).is_err());
    assert_eq!(api.writes, 0);
    api.records.truncate(1);
    api.records[0]["opaque"] = "x".repeat(2 * 1024 * 1024).into();
    assert_eq!(
        editor().plan(change(), &mut api).unwrap_err().code,
        "snapshot_byte_budget"
    );
    assert_eq!(api.writes, 0);
}
