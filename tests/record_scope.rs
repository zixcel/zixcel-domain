mod record_support;
use record_support::*;
use zixcel_domain::record_editor::{Edit, RecordType};
#[test]
fn account_and_record_scope_mismatch_never_issues_approval() {
    let mut wrong_account = Api {
        wrong_scope: true,
        ..Default::default()
    };
    assert_eq!(
        editor()
            .plan(
                Edit::Create {
                    record: data(RecordType::A)
                },
                &mut wrong_account
            )
            .unwrap_err()
            .code,
        "wrong_zone_scope"
    );
    for record in [
        serde_json::json!({"id":RECORD,"name":"evil.test","type":"A"}),
        serde_json::json!({"id":RECORD,"name":"app.example.test","zone_id":"9".repeat(32),"type":"A"}),
    ] {
        let mut api = Api {
            records: vec![record],
            ..Default::default()
        };
        assert_eq!(
            editor().plan(change(), &mut api).unwrap_err().code,
            "wrong_record_scope"
        );
        assert_eq!(api.writes, 0);
    }
}
#[test]
fn unsupported_types_type_changes_and_unchanged_updates_are_rejected() {
    let mut api = Api {
        records: vec![existing()],
        ..Default::default()
    };
    assert_eq!(
        editor()
            .plan(
                Edit::Update {
                    record_id: RECORD.into(),
                    record: data(RecordType::TXT)
                },
                &mut api
            )
            .unwrap_err()
            .code,
        "record_type_change_refused"
    );
    assert_eq!(
        editor()
            .plan(
                Edit::Update {
                    record_id: RECORD.into(),
                    record: data(RecordType::A)
                },
                &mut api
            )
            .unwrap_err()
            .code,
        "record_unchanged"
    );
    api.records[0]["type"] = "NS".into();
    assert_eq!(
        editor()
            .plan(
                Edit::Delete {
                    record_id: RECORD.into()
                },
                &mut api
            )
            .unwrap_err()
            .code,
        "unsupported_record_type"
    );
    assert_eq!(api.writes, 0);
}

#[test]
fn wrong_zone_id_name_or_inactive_zone_is_refused_before_record_access() {
    for (key, value) in [
        ("id", "9".repeat(32)),
        ("name", "other.test".into()),
        ("status", "pending".into()),
    ] {
        let mut zone = serde_json::json!({"id":ZONE,"name":"example.test","status":"active","account":{"id":ACCOUNT}});
        zone[key] = value.into();
        let mut api = Api {
            zone_override: Some(zone),
            ..Default::default()
        };
        assert_eq!(
            editor()
                .plan(
                    Edit::Create {
                        record: data(RecordType::A)
                    },
                    &mut api
                )
                .unwrap_err()
                .code,
            "wrong_zone_scope"
        );
        assert_eq!(api.reads, 1);
        assert_eq!(api.writes, 0);
    }
}
