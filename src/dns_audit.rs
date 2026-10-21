//! Public DNS diagnostics; mail alignment, business intent and configuration writes stay separate.
use crate::{Result, domain_name, error, public_dns, transport::ReadTransport};
use serde_json::{Value, json};
use std::collections::BTreeMap;
pub fn observe(
    http: &mut impl ReadTransport,
    input: &str,
    now: u64,
    authority: bool,
) -> Result<Value> {
    let domain = domain_name(input)?;
    let mut observations = BTreeMap::new();
    let mut findings = Vec::new();
    for (key, name, kind) in [
        ("dmarc", format!("_dmarc.{domain}"), "TXT"),
        ("spf", domain.clone(), "TXT"),
        ("mx", domain.clone(), "MX"),
        ("ns", domain.clone(), "NS"),
        ("ds", domain.clone(), "DS"),
        ("caa", domain.clone(), "CAA"),
    ] {
        match public_dns::query(http, &name, kind) {
            Ok(query) => {
                if key == "dmarc" {
                    let txt: Vec<_> = query.answers.iter().map(|a| a.data.clone()).collect();
                    match crate::dmarc::parse(&txt) {
                        Ok(policy) => {
                            if policy.policy == "none" {
                                findings.push(json!({"code":"dmarc_monitoring_only","change_requires_sender_inventory":true}));
                            }
                            observations
                                .insert("dmarc_policy", json!({"state":"supported","data":policy}));
                        }
                        Err(error) => {
                            findings.push(json!({"code":error.code,"automatic_fix":false}));
                            observations.insert(
                                "dmarc_policy",
                                json!({"state":"partial","reason":error.code}),
                            );
                        }
                    }
                }
                observations.insert(key, json!({"state":"supported","data":query}));
            }
            Err(error) => {
                observations.insert(key,json!({"state":if matches!(error.http_status,Some(401|403)){"denied"}else{"unobserved"},"reason":error.code}));
            }
        }
    }
    observations.insert(
        "authority",
        if authority {
            match http.authority(&domain) {
                Ok(value) => json!({"state":"supported","data":value}),
                Err(error) => json!({"state":"unobserved","reason":error.code}),
            }
        } else {
            json!({"state":"unobserved","reason":"not_requested"})
        },
    );
    Ok(
        json!({"schema":"zix-domain-dns-audit/v1","domain":domain,"observed_at":now,
        "observations":observations,"findings":findings,"writes_performed":false,
        "mail_alignment":"unobserved","zone_inventory_complete":false,
        "dnssec_signature_validation":"resolver_AD_assertion_only"}),
    )
}
pub fn validate_report(value: &Value, domain: &str, now: u64) -> Result<()> {
    if value["schema"] != "zix-domain-dns-audit/v1"
        || value["domain"] != domain_name(domain)?
        || value["writes_performed"] != false
    {
        return Err(error("wrong_dns_report"));
    }
    let at = value["observed_at"]
        .as_u64()
        .ok_or_else(|| error("invalid_observation_date"))?;
    if at > now.saturating_add(60) || now.saturating_sub(at) > 3600 {
        return Err(error("stale_dns_report"));
    }
    Ok(())
}
