use super::{Delegation, referral::referral};
use crate::{Result, domain_name, error};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use std::{
    net::{Ipv4Addr, UdpSocket},
    time::{Duration, Instant},
};
pub fn details(input: &str) -> Result<Delegation> {
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
            next = Some((value, *server));
            break;
        }
        let ((owner, names, addresses), parent_server) =
            next.ok_or_else(|| error("delegation_unavailable"))?;
        if owner == target {
            return Ok(Delegation {
                domain: target,
                nameservers: names,
                parent_server,
                child_addresses: addresses,
            });
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
