#![allow(dead_code)]
use serde_json::{Value, json};
use zixcel_domain::{
    Error, Result,
    record_editor::{Edit, Editor, RecordData, RecordType, Scope},
    transport::{ReadTransport, RecordWriteTransport, WriteTransport},
};
pub const ACCOUNT: &str = "11111111111111111111111111111111";
pub const ZONE: &str = "22222222222222222222222222222222";
pub const RECORD: &str = "33333333333333333333333333333333";
pub const CREATED: &str = "44444444444444444444444444444444";
pub fn editor() -> Editor {
    Editor::new(Scope {
        account: ACCOUNT.into(),
        zone: ZONE.into(),
        domain: "example.test".into(),
    })
    .unwrap()
}
pub fn data(kind: RecordType) -> RecordData {
    let content = match kind {
        RecordType::A => "192.0.2.7",
        RecordType::AAAA => "2001:db8::7",
        RecordType::CNAME | RecordType::MX => "destination.example.test",
        RecordType::TXT => "v=spf1 -all",
    };
    RecordData {
        kind,
        name: "app.example.test".into(),
        content: content.into(),
        ttl: 3600,
        proxied: false,
        priority: (kind == RecordType::MX).then_some(10),
    }
}
pub fn existing() -> Value {
    let mut value = serde_json::to_value(data(RecordType::A)).unwrap();
    value["id"] = RECORD.into();
    value["comment"] = "keep".into();
    value["tags"] = json!(["owner:synthetic"]);
    value["settings"] = json!({"ipv4_only":true});
    value["modified_on"] = "before".into();
    value
}
#[derive(Default)]
pub struct Api {
    pub records: Vec<Value>,
    pub writes: usize,
    pub reads: usize,
    pub method: String,
    pub wrong_scope: bool,
    pub zone_override: Option<Value>,
    pub fail_write: bool,
    pub lost_response: bool,
    pub fail_readback: bool,
    pub lose_metadata: bool,
    pub collateral: bool,
    pub ignore_write: bool,
}
pub fn change() -> Edit {
    let mut record = data(RecordType::A);
    record.content = "192.0.2.8".into();
    Edit::Update {
        record_id: RECORD.into(),
        record,
    }
}

mod read;
mod write;
