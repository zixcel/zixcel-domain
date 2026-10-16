use crate::{Result, cloudflare, domain_name, error, transport::ReadTransport, valid_id};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub account: String,
    pub zone: String,
    pub domain: String,
}
impl Scope {
    pub(crate) fn validate(mut self) -> Result<Self> {
        if !valid_id(&self.account) || !valid_id(&self.zone) {
            return Err(error("invalid_scope"));
        }
        self.account.make_ascii_lowercase();
        self.zone.make_ascii_lowercase();
        self.domain = domain_name(&self.domain)?;
        Ok(self)
    }
    pub(crate) fn records_path(&self) -> String {
        format!("/zones/{}/dns_records", self.zone)
    }
}
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Snapshot {
    pub zone: Value,
    pub records: Vec<Value>,
}

pub(crate) fn read(transport: &mut impl ReadTransport, scope: &Scope) -> Result<Snapshot> {
    let envelope = transport.get(&format!("/zones/{}", scope.zone))?;
    if envelope["success"] != true {
        return Err(error("provider_failed"));
    }
    let zone = &envelope["result"];
    if zone["id"] != scope.zone
        || zone["account"]["id"] != scope.account
        || zone["name"] != scope.domain
        || zone["status"] != "active"
    {
        return Err(error("wrong_zone_scope"));
    }
    let mut records = cloudflare::records(transport, &scope.zone)?;
    for record in &records {
        let name = record["name"]
            .as_str()
            .ok_or_else(|| error("invalid_record_owner"))?;
        if !(name == scope.domain || name.ends_with(&format!(".{}", scope.domain)))
            || record.get("zone_id").is_some_and(|v| v != &scope.zone)
            || record.get("zone_name").is_some_and(|v| v != &scope.domain)
        {
            return Err(error("wrong_record_scope"));
        }
    }
    records.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let snapshot = Snapshot {
        zone: json!({"id":zone["id"], "account":{"id":zone["account"]["id"]},
            "name":zone["name"], "status":zone["status"]}),
        records,
    };
    if serde_json::to_vec(&snapshot)
        .map_err(|_| error("invalid_snapshot"))?
        .len()
        > 2 * 1024 * 1024
    {
        return Err(error("snapshot_byte_budget"));
    }
    Ok(snapshot)
}
