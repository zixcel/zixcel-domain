//! Direct DNS evidence from iterated public delegation, without claiming signature validation.
use crate::{Result, error};
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, UdpSocket},
    time::{Duration, Instant},
};
pub fn decode(response: &Message, query: &Message, kind: RecordType) -> Result<Vec<String>> {
    if query.queries.len() != 1
        || response.metadata.id != query.metadata.id
        || response.queries != query.queries
        || response.metadata.message_type != MessageType::Response
        || response.metadata.response_code != ResponseCode::NoError
        || response.metadata.truncation
        || !response.metadata.authoritative
        || response.answers.len() > 100
    {
        return Err(error("invalid_authoritative_response"));
    }
    let target = &query.queries[0].name;
    let mut records = Vec::new();
    for r in &response.answers {
        if &r.name != target {
            return Err(error("wrong_authoritative_owner"));
        }
        if r.data.record_type() == kind {
            records.push(r.data.to_string());
        } else if r.data.record_type() != RecordType::RRSIG {
            return Err(error("unexpected_authoritative_record"));
        }
    }
    if records.is_empty()
        && !response.authorities.iter().any(|r| {
            let owner = r.name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
            let name = target.to_ascii().trim_end_matches('.').to_ascii_lowercase();
            matches!(r.data, RData::SOA(_))
                && (owner.is_empty() || name == owner || name.ends_with(&format!(".{owner}")))
        })
    {
        return Err(error("authoritative_absence_unproven"));
    }
    records.sort();
    records.dedup();
    Ok(records)
}
fn direct(
    server: Ipv4Addr,
    domain: &str,
    kind: RecordType,
    deadline: Instant,
) -> Result<Vec<String>> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| error("authority_time_budget"))?;
    let mut query = Message::query();
    query.metadata.recursion_desired = false;
    query.queries.push(Query::query(
        Name::from_ascii(format!("{domain}.")).map_err(|_| error("invalid_domain"))?,
        kind,
    ));
    let socket =
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|_| error("authority_transport"))?;
    socket
        .set_read_timeout(Some(remaining.min(Duration::from_secs(2))))
        .map_err(|_| error("authority_transport"))?;
    socket
        .connect((server, 53))
        .map_err(|_| error("authority_transport"))?;
    socket
        .send(&query.to_vec().map_err(|_| error("invalid_dns_request"))?)
        .map_err(|_| error("authority_transport"))?;
    let mut bytes = [0; 4096];
    let size = socket
        .recv(&mut bytes)
        .map_err(|_| error("authority_transport"))?;
    decode(
        &Message::from_vec(&bytes[..size]).map_err(|_| error("invalid_authoritative_response"))?,
        &query,
        kind,
    )
}
fn evidence(result: Result<Vec<String>>) -> Value {
    match result {
        Ok(rows) => json!({"state":"supported","records":rows}),
        Err(error) => json!({"state":"unobserved","reason":error.code}),
    }
}
pub fn observe(domain: &str) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(24);
    let parent = crate::delegation::details(domain)?;
    let ds = evidence(direct(
        parent.parent_server,
        &parent.domain,
        RecordType::DS,
        deadline,
    ));
    let query_child = |kind| match parent.child_addresses.first() {
        Some(ip) => direct(*ip, &parent.domain, kind, deadline),
        None => Err(error("child_glue_unobserved")),
    };
    Ok(
        json!({"observation":"iterated_parent_and_direct_authority","domain":parent.domain,
        "delegated_nameservers":parent.nameservers,"parent_ds":ds,
        "child_ns":evidence(query_child(RecordType::NS)),"child_soa":evidence(query_child(RecordType::SOA)),
        "dnssec_signature_validation":"unobserved","writes_performed":false}),
    )
}
