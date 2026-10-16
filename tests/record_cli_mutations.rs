#![cfg(unix)]
mod record_cli_support;
mod record_support;
use record_cli_support::session;
use record_support::*;
use serde_json::json;
use zixcel_domain::record_editor::{Edit, RecordType};

#[test]
fn all_types_update_and_delete_through_the_same_session_protocol() {
    for kind in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::TXT,
        RecordType::MX,
    ] {
        let mut record = existing();
        for (key, value) in serde_json::to_value(data(kind))
            .unwrap()
            .as_object()
            .unwrap()
        {
            record[key] = value.clone();
        }
        let mut api = Api {
            records: vec![record],
            ..Default::default()
        };
        session(&mut api, |client| {
            let mut desired = data(kind);
            desired.ttl = 7200;
            for edit in [
                Edit::Update {
                    record_id: RECORD.into(),
                    record: desired,
                },
                Edit::Delete {
                    record_id: RECORD.into(),
                },
            ] {
                let planned = client.request(json!({"action":"plan","edit":edit}));
                let hash = planned["result"]["sha256"].as_str().unwrap();
                let reply = client.request(json!({"action":"apply","sha256":hash}));
                assert_eq!(reply["result"]["state"], "provider_verified");
                assert_eq!(reply["result"]["writes_attempted"], 1);
            }
        });
        assert_eq!(api.writes, 2);
        assert_eq!(api.method, "DELETE");
        assert!(api.records.is_empty());
    }
}
