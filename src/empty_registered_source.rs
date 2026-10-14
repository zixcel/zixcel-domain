//! Explicit repair of an empty registered zone with unavailable public DNS.
use crate::{
    Result, domain_name,
    domain_release::{Source, SourceMode},
    error, public_dns,
    transport::ReadTransport,
    valuedomain,
};

pub(crate) fn source(
    registrar: &mut impl ReadTransport,
    public: &mut impl ReadTransport,
    domain: &str,
) -> Result<Source> {
    let domain = domain_name(domain)?;
    if !valuedomain::domains(registrar)?
        .iter()
        .any(|entry| entry.domain == domain)
    {
        return Err(error("domain_not_in_inventory"));
    }
    let mut registrar_ns = valuedomain::nameservers(registrar, &domain)?;
    registrar_ns.sort();
    registrar_ns.dedup();
    let mut parent_ns = public.delegation(&domain)?;
    parent_ns.sort();
    parent_ns.dedup();
    let expected = [
        "ns11.value-domain.com",
        "ns12.value-domain.com",
        "ns13.value-domain.com",
    ];
    if registrar_ns != parent_ns || parent_ns != expected {
        return Err(error("empty_source_delegation_mismatch"));
    }
    let stored = valuedomain::stored_dns(registrar, &domain)?;
    if stored.ns_type != "valuedomain11" || !stored.records.trim().is_empty() {
        return Err(error("empty_registered_source_required"));
    }
    // A SERVFAIL is not an empty export. This mode uses the owner's empty
    // registered configuration; public SOA/mail remain explicitly unobserved.
    if !public_dns::query(public, &domain, "DS")?.answers.is_empty() {
        return Err(error("dnssec_transition_required"));
    }
    Ok(Source {
        source_mode: SourceMode::EmptyRegisteredUnserved,
        domain,
        registrar_nameservers: registrar_ns,
        public_nameservers: vec![],
        parent_delegation_nameservers: parent_ns,
        public_soa: String::new(),
        dns_service: stored.ns_type,
        records: stored.records,
        ttl: u32::try_from(stored.ttl).map_err(|_| error("invalid_dns"))?,
        parent_ds_present: false,
        observed_apex_mail: vec![],
    })
}
