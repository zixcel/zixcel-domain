#![cfg(unix)]
mod record_cli_support;
mod record_support;
use record_cli_support::session;
use record_support::*;
use serde_json::json;
use zixcel_domain::record_editor::{Edit, RecordType};

#[test]
fn cli_plan_apply_round_trip_uses_all_types_and_refuses_replay() {
    for kind in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::TXT,
        RecordType::MX,
    ] {
        let mut api = Api::default();
        session(&mut api, |client| {
            let plan =
                client.request(json!({"action":"plan","edit":Edit::Create {record:data(kind)}}));
            let hash = plan["result"]["sha256"].as_str().unwrap();
            let reply = client.request(json!({"action":"apply","sha256":hash}));
            assert_eq!(reply["result"]["state"], "provider_verified");
            assert_eq!(
                client.request(json!({"action":"apply","sha256":hash}))["error"]["code"],
                "unissued_or_consumed_plan"
            );
        });
        assert_eq!(api.writes, 1);
        assert_eq!(api.records[0]["type"], serde_json::to_value(kind).unwrap());
    }
}

#[test]
fn approval_does_not_cross_sessions_and_lost_response_is_not_replayed() {
    let mut api = Api::default();
    let mut hash = String::new();
    session(&mut api, |client| {
        hash =
            client
                .request(json!({"action":"plan","edit":Edit::Create {record:data(RecordType::A)}}))
                ["result"]["sha256"]
                .as_str()
                .unwrap()
                .into();
    });
    assert_eq!(api.writes, 0);
    session(&mut api, |client| {
        assert_eq!(
            client.request(json!({"action":"apply","sha256":hash}))["error"]["code"],
            "unissued_or_consumed_plan"
        );
    });
    assert_eq!(api.reads, 2);
    api.lost_response = true;
    session(&mut api, |client| {
        let plan = client
            .request(json!({"action":"plan","edit":Edit::Create {record:data(RecordType::A)}}));
        let hash = plan["result"]["sha256"].as_str().unwrap();
        assert_eq!(
            client.request(json!({"action":"apply","sha256":hash}))["result"]["state"],
            "outcome_unknown"
        );
        assert_eq!(
            client.request(json!({"action":"apply","sha256":hash}))["error"]["code"],
            "unissued_or_consumed_plan"
        );
    });
    assert_eq!(api.writes, 1);
}
