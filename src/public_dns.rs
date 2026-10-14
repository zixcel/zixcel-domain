//! Bounded recursive observations, never a complete zone export.
use crate::{Result, domain_name, error, transport::ReadTransport};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Query {
    pub domain: String,
    pub record_type: String,
    pub answers: Vec<Answer>,
    pub dnssec_validated: bool,
    pub observation: &'static str,
    pub zone_inventory_complete: bool,
}
#[derive(Debug, Serialize)]
pub struct Answer {
    pub name: String,
    pub ttl: u32,
    pub data: String,
}

pub fn query(transport: &mut impl ReadTransport, domain: &str, record_type: &str) -> Result<Query> {
    let domain = domain_name(domain)?;
    let record_type = record_type.to_ascii_uppercase();
    let number = match record_type.as_str() {
        "A" => 1,
        "NS" => 2,
        "SOA" => 6,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "DS" => 43,
        "CAA" => 257,
        _ => return Err(error("unsupported_dns_query")),
    };
    let response = transport.get(&format!("/dns-query?name={domain}&type={record_type}"))?;
    match response["Status"].as_u64() {
        Some(0) => {}
        Some(2) => return Err(error("dns_servfail")),
        Some(3) => return Err(error("dns_nxdomain")),
        Some(5) => return Err(error("dns_refused")),
        _ => return Err(error("dns_query_failed")),
    }
    if response["TC"].as_bool() != Some(false) {
        return Err(error("dns_truncated"));
    }
    let questions = response["Question"]
        .as_array()
        .ok_or_else(|| error("invalid_dns_response"))?;
    if questions.len() != 1
        || questions[0]["type"].as_u64() != Some(number)
        || domain_name(
            questions[0]["name"]
                .as_str()
                .ok_or_else(|| error("invalid_dns_response"))?,
        )? != domain
    {
        return Err(error("wrong_dns_question"));
    }
    let mut answers = Vec::new();
    if let Some(records) = response.get("Answer") {
        let records = records
            .as_array()
            .ok_or_else(|| error("invalid_dns_response"))?;
        if records.len() > 1000 {
            return Err(error("record_budget"));
        }
        for record in records {
            let name = domain_name(
                record["name"]
                    .as_str()
                    .ok_or_else(|| error("invalid_dns_response"))?,
            )?;
            if name != domain || record["type"].as_u64() != Some(number) {
                return Err(error("unexpected_dns_answer"));
            }
            let data = record["data"]
                .as_str()
                .ok_or_else(|| error("invalid_dns_response"))?;
            if data.len() > 8192 {
                return Err(error("response_budget"));
            }
            let ttl = record["TTL"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| error("invalid_dns_response"))?;
            answers.push(Answer {
                name,
                ttl,
                data: data.to_owned(),
            });
        }
    }
    Ok(Query {
        domain,
        record_type,
        answers,
        dnssec_validated: response["AD"].as_bool().unwrap_or(false),
        observation: "recursive_resolver",
        zone_inventory_complete: false,
    })
}
