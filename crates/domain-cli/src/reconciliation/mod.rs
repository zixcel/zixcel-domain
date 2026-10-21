//! Cross-source review only. Provider grants and fresh record execution remain separate.
mod dnssec;
mod settings;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use zixcel_cloudflare_observer::Report;
use zixcel_domain::{Result, error};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub cloudflare: Report,
    pub dns: Value,
    pub registrar: Option<Value>,
}
pub(super) fn names(value: &Value) -> Option<BTreeSet<String>> {
    let rows = value
        .as_array()
        .filter(|r| !r.is_empty() && r.len() <= 16)?;
    let names: Option<BTreeSet<_>> = rows
        .iter()
        .map(|v| zixcel_domain::domain_name(v.as_str()?).ok())
        .collect();
    names.filter(|set| set.len() == rows.len())
}
pub(super) fn data<'a>(report: &'a Report, key: &str) -> Option<&'a Value> {
    report.observations.get(key)?.supported()
}
pub fn review(bundle: &Bundle, now: u64) -> Result<Value> {
    bundle.cloudflare.verify(now).map_err(error)?;
    if now.saturating_sub(bundle.cloudflare.observed_at) > 3600 {
        return Err(error("stale_cloudflare_report"));
    }
    let zone = bundle
        .cloudflare
        .scope
        .zone
        .as_ref()
        .ok_or_else(|| error("zone_scope_required"))?;
    if let Some(value) = data(&bundle.cloudflare, "zone")
        && (value["id"] != zone.id
            || value["name"] != zone.domain
            || value["account_id"] != bundle.cloudflare.scope.account)
    {
        return Err(error("zone_evidence_scope_mismatch"));
    }
    zixcel_domain::dns_audit::validate_report(&bundle.dns, &zone.domain, now)?;
    let mut findings = Vec::new();
    let authority = &bundle.dns["observations"]["authority"];
    let parent = if authority["state"] == "supported" {
        names(&authority["data"]["delegated_nameservers"])
    } else {
        None
    };
    let assigned = data(&bundle.cloudflare, "zone").and_then(|z| names(&z["name_servers"]));
    if let (Some(parent), Some(assigned)) = (&parent, assigned)
        && parent != &assigned
    {
        findings.push(json!({"code":"cloudflare_delegation_mismatch","severity":"error","automatic_fix":false}));
    }
    if let Some(registrar) = &bundle.registrar {
        validate_registrar(registrar, &zone.domain, now)?;
        if let (Some(parent), Some(configured)) =
            (&parent, names(&registrar["nameservers"]["data"]))
            && parent != &configured
        {
            findings.push(json!({"code":"registrar_live_delegation_mismatch","severity":"error","automatic_fix":false}));
        }
    }
    dnssec::check(&bundle.cloudflare, &bundle.dns, &mut findings)?;
    settings::check(&bundle.cloudflare, &bundle.dns, &zone.domain, &mut findings)?;
    let states: std::collections::BTreeMap<_, _> = bundle
        .cloudflare
        .observations
        .iter()
        .map(|(k, v)| (k, &v.state))
        .collect();
    Ok(
        json!({"schema":"zix-domain-reconciliation/v1","domain":zone.domain,"account":bundle.cloudflare.scope.account,
        "zone":zone.id,"source_sha256":zixcel_cloudflare_observer::digest(&serde_json::to_value(bundle).map_err(|_|error("invalid_bundle"))?),
        "cloudflare_states":states,"findings":findings,"parent_delegation_observed":parent.is_some(),
        "registrar_observed":bundle.registrar.is_some(),"writes_performed":false,"executable":false,
        "approval_required":true,"fresh_record_plan_required_for_changes":true,"evidence_authenticity":"not_established_by_hash",
        "unobserved":["local_cryptographic_dnssec_validation","sender_spf_dkim_alignment","contact_delivery","frontend_and_server_turnstile_verification"]}),
    )
}
fn validate_registrar(v: &Value, domain: &str, now: u64) -> Result<()> {
    let at = v["observed_at"]
        .as_u64()
        .ok_or_else(|| error("invalid_registrar_date"))?;
    if v["schema"] != "zix-domain-registrar-observation/v1"
        || v["domain"] != domain
        || v["registration"]["domain"] != domain
        || v["writes_performed"] != false
        || at > now.saturating_add(60)
        || now.saturating_sub(at) > 3600
    {
        return Err(error("wrong_or_stale_registrar_report"));
    }
    Ok(())
}
