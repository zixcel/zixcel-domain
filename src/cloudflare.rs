use crate::{Result, domain_name, error, transport::ReadTransport, valid_id};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub nameservers: Vec<String>,
}

fn list(transport: &mut impl ReadTransport, path: &str) -> Result<Vec<Value>> {
    let mut output = Vec::new();
    let mut total = None;
    let mut seen = BTreeSet::new();
    for page in 1..=100 {
        let response = transport.get(&format!("{path}&per_page=50&page={page}"))?;
        if response["success"].as_bool() != Some(true) {
            return Err(error("provider_failed"));
        }
        let info = &response["result_info"];
        let count = info["total_count"]
            .as_u64()
            .ok_or_else(|| error("invalid_pagination"))?;
        if count > 5000
            || info["page"].as_u64() != Some(page)
            || total.is_some_and(|previous| previous != count)
        {
            return Err(error("inconsistent_inventory"));
        }
        total = Some(count);
        let records = response["result"]
            .as_array()
            .ok_or_else(|| error("invalid_inventory"))?;
        let remaining = count
            .checked_sub(output.len() as u64)
            .ok_or_else(|| error("invalid_pagination"))?;
        if records.len() as u64 != remaining.min(50) {
            return Err(error("incomplete_inventory"));
        }
        for record in records {
            let id = record["id"]
                .as_str()
                .ok_or_else(|| error("invalid_resource"))?;
            if !valid_id(id) || !seen.insert(id.to_owned()) {
                return Err(error("invalid_resource"));
            }
            output.push(record.clone());
        }
        if output.len() as u64 == count {
            return Ok(output);
        }
    }
    Err(error("page_budget"))
}

pub fn zones(transport: &mut impl ReadTransport, account: &str) -> Result<Vec<Zone>> {
    if !valid_id(account) {
        return Err(error("invalid_account"));
    }
    list(transport, &format!("/zones?account.id={account}"))?
        .into_iter()
        .map(|record| {
            if record["account"]["id"].as_str() != Some(account) {
                return Err(error("wrong_account"));
            }
            let nameservers = record["name_servers"]
                .as_array()
                .ok_or_else(|| error("invalid_zone"))?
                .iter()
                .map(|ns| domain_name(ns.as_str().ok_or_else(|| error("invalid_nameserver"))?))
                .collect::<Result<Vec<_>>>()?;
            Ok(Zone {
                id: record["id"]
                    .as_str()
                    .ok_or_else(|| error("invalid_zone"))?
                    .to_owned(),
                domain: domain_name(
                    record["name"]
                        .as_str()
                        .ok_or_else(|| error("invalid_zone"))?,
                )?,
                status: record["status"]
                    .as_str()
                    .ok_or_else(|| error("invalid_zone"))?
                    .to_owned(),
                nameservers,
            })
        })
        .collect()
}

/// Retain vendor record fields to avoid losing MX/TXT/proxy settings in later plans.
pub fn records(transport: &mut impl ReadTransport, zone: &str) -> Result<Vec<Value>> {
    if !valid_id(zone) {
        return Err(error("invalid_zone"));
    }
    list(transport, &format!("/zones/{zone}/dns_records?order=name"))
}
