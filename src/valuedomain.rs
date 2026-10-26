//! VDAPI v2 contracts, checked against the official domain OpenAPI.
use crate::{Result, domain_name, error, transport::ReadTransport};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct Domain {
    pub domain: String,
    pub expiration: Option<String>,
}

pub fn domains(transport: &mut impl ReadTransport) -> Result<Vec<Domain>> {
    let mut domains = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = None;
    for page in 1..=100 {
        let response = transport
            .get(&format!("/domains?limit=50&page={page}"))
            .map_err(|error| error.for_operation("list_domains"))?;
        let paging = &response["paging"];
        let count = paging["max"]
            .as_u64()
            .ok_or_else(|| error("invalid_pagination"))?;
        if count > 5000
            || paging["page"].as_u64() != Some(page)
            || paging["limit"].as_u64() != Some(50)
            || total.is_some_and(|previous| previous != count)
        {
            return Err(error("inconsistent_inventory"));
        }
        total = Some(count);
        let records = response["results"]
            .as_array()
            .ok_or_else(|| error("invalid_domains"))?;
        let remaining = count
            .checked_sub(domains.len() as u64)
            .ok_or_else(|| error("invalid_pagination"))?;
        if records.len() as u64 != remaining.min(50) {
            return Err(error("incomplete_inventory"));
        }
        for record in records {
            let name = domain_name(
                record["domainname"]
                    .as_str()
                    .ok_or_else(|| error("invalid_domain"))?,
            )?;
            if !seen.insert(name.clone()) {
                return Err(error("duplicate_domain"));
            }
            domains.push(Domain {
                domain: name,
                expiration: record["expirationdate"].as_str().map(str::to_owned),
            });
        }
        if domains.len() as u64 == count {
            return Ok(domains);
        }
    }
    Err(error("page_budget"))
}

/// Exclude domains whose effective renewal is disabled. Individual settings
/// override account settings; unknown/missing values fail instead of guessing.
pub fn domains_excluding_auto_renew_disabled(
    transport: &mut impl ReadTransport,
) -> Result<Vec<Domain>> {
    let inventory = domains(transport)?;
    let mut retained = Vec::new();
    for domain in inventory {
        let response = transport
            .get(&format!("/domains/{}/autorenew", domain.domain))
            .map_err(|error| error.for_operation("read_auto_renew"))?;
        verify_domain(&response, &domain.domain)?;
        if effective_auto_renew(&response["results"])? {
            retained.push(domain);
        }
    }
    Ok(retained)
}

pub fn effective_auto_renew(settings: &serde_json::Value) -> Result<bool> {
    match settings["autorenew_domain"].as_u64() {
        Some(9) => Ok(false),
        Some(10) => Ok(true),
        Some(0) => match settings["autorenew_all"].as_u64() {
            Some(0 | 9) => Ok(false),
            Some(10 | 11) => Ok(true),
            _ => Err(error("invalid_auto_renew")),
        },
        _ => Err(error("invalid_auto_renew")),
    }
}

#[derive(Debug, Serialize)]
pub struct DomainSettings {
    pub domain: String,
    pub nameservers: Vec<String>,
    /// Registrar-stored DNS text: NOT proof that ValueDomain serves authoritative DNS.
    pub stored_dns_records: String,
    pub stored_dns_type: String,
    pub stored_dns_ttl: u64,
    pub authority_verified: bool,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredDns {
    pub domain: String,
    pub records: String,
    pub ns_type: String,
    pub ttl: u64,
    pub authority_verified: bool,
}

pub fn nameservers(transport: &mut impl ReadTransport, input: &str) -> Result<Vec<String>> {
    let domain = domain_name(input)?;
    let response = transport
        .get(&format!("/domains/{domain}/nameserver"))
        .map_err(|error| error.for_operation("read_nameservers"))?;
    verify_domain(&response, &domain)?;
    let nameservers = response["results"]["ns"]
        .as_array()
        .ok_or_else(|| error("invalid_nameservers"))?
        .iter()
        .map(|value| domain_name(value.as_str().ok_or_else(|| error("invalid_nameserver"))?))
        .collect::<Result<Vec<_>>>()?;
    if nameservers.len() > 13 {
        return Err(error("invalid_nameservers"));
    }
    Ok(nameservers)
}

fn verify_domain(response: &serde_json::Value, domain: &str) -> Result<()> {
    let actual = response["results"]["domainname"]
        .as_str()
        .ok_or_else(|| error("invalid_settings"))?;
    if domain_name(actual)? != domain {
        return Err(error("wrong_domain"));
    }
    Ok(())
}

pub fn stored_dns(transport: &mut impl ReadTransport, input: &str) -> Result<StoredDns> {
    let domain = domain_name(input)?;
    let response = transport
        .get(&format!("/domains/{domain}/dns"))
        .map_err(|error| error.for_operation("read_stored_dns"))?;
    verify_domain(&response, &domain)?;
    Ok(StoredDns {
        domain,
        records: response["results"]["records"]
            .as_str()
            .ok_or_else(|| error("invalid_dns"))?
            .to_owned(),
        ns_type: response["results"]["ns_type"]
            .as_str()
            .ok_or_else(|| error("invalid_dns"))?
            .to_owned(),
        ttl: response["results"]["ttl"]
            .as_u64()
            .or_else(|| response["results"]["ttl"].as_str()?.parse().ok())
            .ok_or_else(|| error("invalid_dns"))?,
        authority_verified: false,
    })
}

/// The ns1..ns5 service is separate from registrar-stored ns11 DNS.
pub fn free_dns(transport: &mut impl ReadTransport, input: &str) -> Result<StoredDns> {
    let domain = domain_name(input)?;
    let response = transport
        .get(&format!("/freedns/{domain}"))
        .map_err(|error| error.for_operation("read_free_dns"))?;
    verify_domain(&response, &domain)?;
    let value = &response["results"];
    let ttl = value["ttl"]
        .as_u64()
        .or_else(|| value["ttl"].as_str()?.parse().ok())
        .ok_or_else(|| error("invalid_dns"))?;
    Ok(StoredDns {
        domain,
        records: value["records"]
            .as_str()
            .ok_or_else(|| error("invalid_dns"))?
            .to_owned(),
        ns_type: "valuedomain1".to_owned(),
        ttl,
        authority_verified: false,
    })
}

pub fn settings(transport: &mut impl ReadTransport, input: &str) -> Result<DomainSettings> {
    let domain = domain_name(input)?;
    let nameservers = nameservers(transport, &domain)?;
    let dns = stored_dns(transport, &domain)?;
    Ok(DomainSettings {
        domain,
        nameservers,
        stored_dns_records: dns.records,
        stored_dns_type: dns.ns_type,
        stored_dns_ttl: dns.ttl,
        authority_verified: false,
    })
}
