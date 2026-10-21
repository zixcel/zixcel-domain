use crate::{Result, domain_name, error};
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::RData,
};
use std::net::Ipv4Addr;
fn public_address(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19)))
}

pub(super) fn referral(
    response: &Message,
    query: &Message,
    target: &str,
) -> Result<(String, Vec<String>, Vec<Ipv4Addr>)> {
    if response.metadata.id != query.metadata.id
        || response.queries != query.queries
        || response.metadata.message_type != MessageType::Response
        || response.metadata.response_code != ResponseCode::NoError
        || response.metadata.truncation
        || response.metadata.authoritative
    {
        return Err(error("invalid_delegation_response"));
    }
    let mut owner = None;
    let mut names = Vec::new();
    for record in &response.authorities {
        if let RData::NS(ns) = &record.data {
            let name = record.name.to_ascii().trim_end_matches('.').to_lowercase();
            if target != name && !target.ends_with(&format!(".{name}")) {
                return Err(error("unrelated_delegation"));
            }
            if owner.as_ref().is_some_and(|old| old != &name) {
                return Err(error("ambiguous_delegation"));
            }
            owner = Some(name);
            names.push(domain_name(&ns.0.to_ascii())?);
        }
    }
    names.sort();
    names.dedup();
    if names.is_empty() || names.len() > 16 {
        return Err(error("delegation_missing"));
    }
    let mut addresses = Vec::new();
    for record in &response.additionals {
        if let RData::A(ip) = record.data
            && names.contains(&record.name.to_ascii().trim_end_matches('.').to_lowercase())
            && public_address(ip.0)
        {
            addresses.push(ip.0);
        }
    }
    addresses.sort();
    addresses.dedup();
    Ok((owner.unwrap(), names, addresses))
}
