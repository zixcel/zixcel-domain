mod record_support;
use record_support::*;
use serde_json::{Value, json};
use std::io::Cursor;
use zixcel_domain::{record_cli, record_editor::Scope};

fn scope() -> Scope {
    Scope {
        account: ACCOUNT.into(),
        zone: ZONE.into(),
        domain: "example.test".into(),
    }
}
fn request(command: Value) -> String {
    format!("{}\n", json!({"protocol":1,"command":command}))
}

#[test]
fn cancellation_discards_approval_and_never_processes_a_queued_write() {
    for stop_explicitly in [false, true] {
        let planned = request(json!({"action":"plan","edit":change()}));
        let stop = request(json!({"action":"stop"}));
        let queued = request(json!({"action":"apply","sha256":"0".repeat(64)}));
        let input = if stop_explicitly {
            format!("{planned}{stop}{queued}")
        } else {
            planned.clone()
        };
        let mut input = Cursor::new(input.into_bytes());
        let mut output = Vec::new();
        let mut api = Api {
            records: vec![existing()],
            ..Default::default()
        };
        record_cli::serve(scope(), &mut input, &mut output, &mut api).unwrap();
        let replies: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(api.writes, 0);
        assert_eq!(api.records, vec![existing()]);
        assert_eq!(replies.len(), if stop_explicitly { 2 } else { 1 });
        if stop_explicitly {
            assert_eq!(replies[1]["result"]["session_closed"], "requested");
            assert_eq!(input.position() as usize, planned.len() + stop.len());
        }
        let old_hash = replies[0]["result"]["sha256"].as_str().unwrap();
        let reads = api.reads;
        let mut output = Vec::new();
        record_cli::serve(
            scope(),
            Cursor::new(request(json!({"action":"apply","sha256":old_hash}))),
            &mut output,
            &mut api,
        )
        .unwrap();
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["error"]["code"], "unissued_or_consumed_plan");
        assert_eq!((api.reads, api.writes), (reads, 0));
    }
}
