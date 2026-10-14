//! Read-only observations; resolver answers are not direct authoritative-server evidence.
use crate::{
    Result, cloudflare, domain_name, error, transport::ReadTransport, valid_id, valuedomain,
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

/// Classifies declared nameservers only; does not certify live DNS delegation.
pub fn configured_dns(
    nameservers: &[String],
    assigned_cloudflare: Option<&[String]>,
) -> Result<&'static str> {
    let normalized = nameservers
        .iter()
        .map(|ns| domain_name(ns))
        .collect::<Result<BTreeSet<_>>>()?;
    if normalized.is_empty() || normalized.len() != nameservers.len() {
        return Err(error("invalid_nameservers"));
    }
    if let Some(assigned) = assigned_cloudflare {
        let assigned = assigned
            .iter()
            .map(|ns| domain_name(ns))
            .collect::<Result<BTreeSet<_>>>()?;
        if !assigned.is_empty() && normalized == assigned {
            return Ok("cloudflare_assignment_matches");
        }
    }
    let allowed = [
        "ns1.value-domain.com",
        "ns2.value-domain.com",
        "ns3.value-domain.com",
        "ns4.value-domain.com",
        "ns5.value-domain.com",
        "ns11.value-domain.com",
        "ns12.value-domain.com",
        "ns13.value-domain.com",
    ];
    let recognized = normalized
        .iter()
        .filter(|ns| allowed.contains(&ns.as_str()))
        .count();
    Ok(if recognized == normalized.len() {
        "valuedomain_only"
    } else if recognized > 0 {
        "mixed_nameservers"
    } else {
        "external_unverified"
    })
}

#[derive(Debug, Serialize)]
pub struct PublicNameservers {
    pub domain: String,
    pub nameservers: Vec<String>,
    pub dnssec_validated: bool,
    pub observation: &'static str,
}

pub fn public_nameservers(
    transport: &mut impl ReadTransport,
    input: &str,
) -> Result<PublicNameservers> {
    let domain = domain_name(input)?;
    let response = transport.get(&format!("/dns-query?name={domain}&type=NS"))?;
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
        || questions[0]["type"].as_u64() != Some(2)
        || domain_name(
            questions[0]["name"]
                .as_str()
                .ok_or_else(|| error("invalid_dns_response"))?,
        )? != domain
    {
        return Err(error("wrong_dns_question"));
    }
    let answers = response["Answer"]
        .as_array()
        .ok_or_else(|| error("ns_unobserved"))?;
    let mut nameservers = BTreeSet::new();
    for answer in answers {
        if answer["type"].as_u64() != Some(2) {
            return Err(error("unexpected_dns_answer"));
        }
        if domain_name(
            answer["name"]
                .as_str()
                .ok_or_else(|| error("invalid_dns_response"))?,
        )? != domain
        {
            return Err(error("wrong_dns_answer"));
        }
        nameservers.insert(domain_name(
            answer["data"]
                .as_str()
                .ok_or_else(|| error("invalid_dns_response"))?,
        )?);
    }
    if nameservers.is_empty() || nameservers.len() > 13 {
        return Err(error("invalid_nameservers"));
    }
    Ok(PublicNameservers {
        domain,
        nameservers: nameservers.into_iter().collect(),
        dnssec_validated: response["AD"].as_bool().unwrap_or(false),
        observation: "recursive_resolver",
    })
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Observation<T> {
    Available { value: T },
    Unavailable { error: crate::Error },
    NotApplicable { reason: &'static str },
}
impl<T> Observation<T> {
    fn from_result(result: Result<T>, provider: &'static str, operation: &'static str) -> Self {
        match result {
            Ok(value) => Self::Available { value },
            Err(error) => Self::Unavailable {
                error: error.with_context(provider, operation),
            },
        }
    }
    fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }
}

#[derive(Debug, Serialize)]
pub struct RegistrarObservation {
    pub domain: String,
    pub configured_dns: &'static str,
    pub nameservers: Observation<Vec<String>>,
    pub stored_dns: Observation<valuedomain::StoredDns>,
}

#[derive(Debug, Serialize)]
pub struct ZoneRecords {
    pub zone: cloudflare::Zone,
    pub records: Observation<Vec<serde_json::Value>>,
}

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub account_id: String,
    pub observed_from_unix: u64,
    pub observed_until_unix: u64,
    pub registrar_settings: Vec<RegistrarObservation>,
    pub cloudflare_zones: Vec<ZoneRecords>,
    pub writes_performed: bool,
    pub complete_for_dns_plan: bool,
}

fn unix_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| error("clock_unavailable"))
}

/// No partial snapshot can be used as a complete migration input.
pub fn inspect(
    registrar: &mut impl ReadTransport,
    dns: &mut impl ReadTransport,
    account: &str,
) -> Result<Inspection> {
    if !valid_id(account) {
        return Err(error("invalid_account"));
    }
    let observed_from_unix = unix_time()?;
    let domains = valuedomain::domains(registrar)?;
    if domains.len() > 40 {
        return Err(error("inspection_budget"));
    }
    let zones = cloudflare::zones(dns, account)?;
    if zones.len() > 40 {
        return Err(error("inspection_budget"));
    }
    let mut registrar_settings = Vec::new();
    for domain in domains {
        let nameservers = Observation::from_result(
            valuedomain::nameservers(registrar, &domain.domain),
            "valuedomain-v2",
            "read_nameservers",
        );
        let configured_dns = match &nameservers {
            Observation::Available { value } => configured_dns(
                value,
                zones
                    .iter()
                    .find(|zone| zone.domain == domain.domain)
                    .map(|zone| zone.nameservers.as_slice()),
            )
            .unwrap_or("unverified_nameservers"),
            _ => "unavailable",
        };
        // The DNS host's records are the migration input. Do not query unsupported
        // registrar storage when the assigned Cloudflare NS already match.
        let stored_dns = if configured_dns == "cloudflare_assignment_matches" {
            Observation::NotApplicable {
                reason: "dns_hosted_on_cloudflare",
            }
        } else {
            Observation::from_result(
                valuedomain::stored_dns(registrar, &domain.domain),
                "valuedomain-v2",
                "read_stored_dns",
            )
        };
        registrar_settings.push(RegistrarObservation {
            domain: domain.domain,
            configured_dns,
            nameservers,
            stored_dns,
        });
    }
    let mut cloudflare_zones = Vec::new();
    for zone in zones {
        let records = Observation::from_result(
            cloudflare::records(dns, &zone.id),
            "cloudflare",
            "read_zone_records",
        );
        cloudflare_zones.push(ZoneRecords { zone, records });
    }
    let complete_for_dns_plan = registrar_settings.iter().all(|item| {
        item.nameservers.is_available()
            && match item.configured_dns {
                "cloudflare_assignment_matches" => true,
                "valuedomain_only" => item.stored_dns.is_available(),
                _ => false,
            }
    }) && cloudflare_zones
        .iter()
        .all(|item| item.records.is_available() && item.zone.status == "active");
    Ok(Inspection {
        account_id: account.to_owned(),
        observed_from_unix,
        observed_until_unix: unix_time()?,
        registrar_settings,
        cloudflare_zones,
        writes_performed: false,
        complete_for_dns_plan,
    })
}
