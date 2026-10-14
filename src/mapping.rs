//! Explicit organization ownership matched against visible provider inventory.
use crate::{
    DomainBinding, Result, cloudflare::Zone, domain_name, error, validate_bindings,
    valuedomain::Domain,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingInput {
    pub bindings: Vec<DomainBinding>,
    pub registrar_domains: Vec<Domain>,
    pub cloudflare_zones: Vec<Zone>,
    pub cloudflare_account_id: String,
}

#[derive(Debug, Serialize)]
pub struct MappingRow {
    pub organization: String,
    pub domain: String,
    pub registrar_visible: bool,
    pub cloudflare_zone_id: Option<String>,
    pub cloudflare_zone_status: Option<String>,
    pub next_step: &'static str,
}

#[derive(Debug, Serialize)]
pub struct MappingPreview {
    pub rows: Vec<MappingRow>,
    pub unassigned_registrar_domains: Vec<String>,
    pub kind: &'static str,
    pub write_authorized: bool,
}

/// Absence from a token's visible zone list does not prove absence from the account.
pub fn preview(input: &MappingInput) -> Result<MappingPreview> {
    validate_bindings(&input.bindings)?;
    if !crate::valid_id(&input.cloudflare_account_id) {
        return Err(error("invalid_account"));
    }
    if input.registrar_domains.len() > 5000 || input.cloudflare_zones.len() > 5000 {
        return Err(error("inventory_budget"));
    }
    let mut registrar = BTreeSet::new();
    for item in &input.registrar_domains {
        if !registrar.insert(domain_name(&item.domain)?) {
            return Err(error("duplicate_domain"));
        }
    }
    let mut zones = BTreeMap::new();
    let mut zone_ids = BTreeSet::new();
    for zone in &input.cloudflare_zones {
        if !crate::valid_id(&zone.id)
            || !zone_ids.insert(&zone.id)
            || zones.insert(domain_name(&zone.domain)?, zone).is_some()
        {
            return Err(error("invalid_zone_inventory"));
        }
    }
    let mut assigned = BTreeSet::new();
    let mut rows = Vec::new();
    for binding in &input.bindings {
        if binding.cloudflare_account_id != input.cloudflare_account_id {
            return Err(error("wrong_account"));
        }
        let domain = domain_name(&binding.domain)?;
        assigned.insert(domain.clone());
        let registrar_visible = registrar.contains(&domain);
        let zone = zones.get(&domain);
        let next_step = if !registrar_visible {
            "verify_registrar_visibility"
        } else if zone.is_some() {
            "inspect_existing_dns_and_deployment"
        } else {
            "verify_zone_visibility_before_creation_review"
        };
        rows.push(MappingRow {
            organization: binding.organization.clone(),
            domain,
            registrar_visible,
            cloudflare_zone_id: zone.map(|zone| zone.id.clone()),
            cloudflare_zone_status: zone.map(|zone| zone.status.clone()),
            next_step,
        });
    }
    Ok(MappingPreview {
        rows,
        unassigned_registrar_domains: registrar.difference(&assigned).cloned().collect(),
        kind: "read_only_mapping_preview",
        write_authorized: false,
    })
}
