//! Read-only parent delegation observations. Child NS/SOA names are not delegation.
use crate::{Result, domain_name, error};
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use std::{
    net::{Ipv4Addr, UdpSocket},
    time::{Duration, Instant},
};

fn public_address(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19)))
}

fn referral(
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

/// Iterate referrals from fixed root servers; fail closed without complete delegation.
/// No credential, resolver cache, update message, or system command is involved.
pub fn query(input: &str) -> Result<Vec<String>> {
    let target = domain_name(input)?;
    let name = Name::from_ascii(format!("{target}.")).map_err(|_| error("invalid_domain"))?;
    let mut request = Message::query();
    request.queries.push(Query::query(name, RecordType::NS));
    request.metadata.recursion_desired = false;
    let bytes = request.to_vec().map_err(|_| error("invalid_dns_request"))?;
    let deadline = Instant::now() + Duration::from_secs(18);
    let mut servers = vec![
        Ipv4Addr::new(198, 41, 0, 4),
        Ipv4Addr::new(199, 9, 14, 201),
        Ipv4Addr::new(192, 33, 4, 12),
    ];
    let mut previous = String::new();
    for _ in 0..8 {
        let mut next = None;
        for server in servers.iter().take(3) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(error("delegation_time_budget"));
            }
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .map_err(|_| error("delegation_transport"))?;
            socket
                .set_read_timeout(Some(remaining.min(Duration::from_secs(2))))
                .map_err(|_| error("delegation_transport"))?;
            socket
                .connect((*server, 53))
                .map_err(|_| error("delegation_transport"))?;
            socket
                .send(&bytes)
                .map_err(|_| error("delegation_transport"))?;
            let mut buffer = [0u8; 4096];
            let Ok(size) = socket.recv(&mut buffer) else {
                continue;
            };
            let Ok(response) = Message::from_vec(&buffer[..size]) else {
                continue;
            };
            let Ok(value) = referral(&response, &request, &target) else {
                continue;
            };
            next = Some(value);
            break;
        }
        let (owner, names, addresses) = next.ok_or_else(|| error("delegation_unavailable"))?;
        if owner == target {
            return Ok(names);
        }
        if owner == previous || (!previous.is_empty() && !owner.ends_with(&format!(".{previous}")))
        {
            return Err(error("delegation_did_not_advance"));
        }
        if addresses.is_empty() {
            return Err(error("delegation_glue_missing"));
        }
        previous = owner;
        servers = addresses;
    }
    Err(error("delegation_hop_budget"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::OpCode,
        rr::{
            Record,
            rdata::{A, NS},
        },
    };
    fn fixture() -> (Message, Message) {
        let mut q = Message::query();
        q.queries.push(Query::query(
            Name::from_ascii("example.org.").unwrap(),
            RecordType::NS,
        ));
        let mut r = Message::response(q.metadata.id, OpCode::Query);
        r.queries = q.queries.clone();
        r.authorities.push(Record::from_rdata(
            Name::from_ascii("example.org.").unwrap(),
            3600,
            RData::NS(NS(Name::from_ascii("ns1.example.net.").unwrap())),
        ));
        r.additionals.push(Record::from_rdata(
            Name::from_ascii("ns1.example.net.").unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
        ));
        (q, r)
    }
    #[test]
    fn referral_accepts_matching_parent_question_and_public_glue() {
        let (q, r) = fixture();
        let (owner, names, ips) = referral(&r, &q, "example.org").unwrap();
        assert_eq!(owner, "example.org");
        assert_eq!(names, vec!["ns1.example.net"]);
        assert_eq!(ips, vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }
    #[test]
    fn wrong_id_truncation_child_authority_and_unrelated_zone_are_rejected() {
        let (q, r) = fixture();
        let mut bad = r.clone();
        bad.metadata.id = q.metadata.id.wrapping_add(1);
        assert!(referral(&bad, &q, "example.org").is_err());
        let mut bad = r.clone();
        bad.metadata.truncation = true;
        assert!(referral(&bad, &q, "example.org").is_err());
        let mut bad = r.clone();
        bad.metadata.authoritative = true;
        assert!(referral(&bad, &q, "example.org").is_err());
        assert!(referral(&r, &q, "another.org").is_err());
        let mut bad = r;
        bad.queries.clear();
        assert!(referral(&bad, &q, "example.org").is_err());
    }
    #[test]
    fn internal_reserved_and_unrelated_glue_are_not_network_targets() {
        let (q, mut r) = fixture();
        r.additionals.clear();
        for ip in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(198, 18, 0, 1),
        ] {
            r.additionals.push(Record::from_rdata(
                Name::from_ascii("ns1.example.net.").unwrap(),
                3600,
                RData::A(A(ip)),
            ));
        }
        r.additionals.push(Record::from_rdata(
            Name::from_ascii("unrelated.example.net.").unwrap(),
            3600,
            RData::A(A(Ipv4Addr::new(8, 8, 4, 4))),
        ));
        assert!(referral(&r, &q, "example.org").unwrap().2.is_empty());
    }
}
