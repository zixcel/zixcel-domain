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
#[derive(Debug, Serialize)]
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
            .ok_or_else(|| error("invalid_dns"))?,
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
