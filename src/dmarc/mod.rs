//! RFC 7489 record diagnostics, not a mail receiver or proof of SPF/DKIM alignment.
pub(crate) mod edit;
mod txt;
use crate::{Result, error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub policy: String,
    pub subdomain_policy: Option<String>,
    pub percentage: u8,
    pub tags: BTreeMap<String, String>,
    pub sender_alignment_verified: bool,
    pub external_report_authorization_verified: bool,
}
/// Each entry is one TXT RR, with optional DNS presentation-format quoting.
pub fn parse(records: &[String]) -> Result<Policy> {
    if records.len() > 100 {
        return Err(error("dmarc_record_budget"));
    }
    let mut candidates = Vec::new();
    for raw in records {
        let decoded = txt::decode(raw)?;
        if decoded.trim_start().starts_with("v=DMARC1") {
            candidates.push(decoded);
        }
    }
    if candidates.len() != 1 {
        return Err(error(if candidates.is_empty() {
            "dmarc_not_found"
        } else {
            "multiple_dmarc_records"
        }));
    }
    let tags: Vec<_> = candidates[0]
        .trim()
        .trim_end_matches(';')
        .split(';')
        .map(str::trim)
        .collect();
    if tags.len() > 32 || tags.len() < 2 || tags[0] != "v=DMARC1" || !tags[1].starts_with("p=") {
        return Err(error("invalid_dmarc_tag_order"));
    }
    let mut parsed = BTreeMap::new();
    for tag in tags {
        let (key, value) = tag
            .split_once('=')
            .ok_or_else(|| error("invalid_dmarc_tag"))?;
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty()
            || value.is_empty()
            || value.chars().any(char::is_control)
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || parsed.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(error("invalid_or_duplicate_dmarc_tag"));
        }
    }
    for key in ["p", "sp"] {
        if parsed
            .get(key)
            .is_some_and(|v| !["none", "quarantine", "reject"].contains(&v.as_str()))
        {
            return Err(error("invalid_dmarc_policy"));
        }
    }
    for key in ["adkim", "aspf"] {
        if parsed
            .get(key)
            .is_some_and(|v| !["r", "s"].contains(&v.as_str()))
        {
            return Err(error("invalid_dmarc_alignment"));
        }
    }
    let percentage = parsed
        .get("pct")
        .map(|v| {
            v.parse::<u8>()
                .map_err(|_| error("invalid_dmarc_percentage"))
        })
        .transpose()?
        .unwrap_or(100);
    if percentage > 100 {
        return Err(error("invalid_dmarc_percentage"));
    }
    Ok(Policy {
        policy: parsed["p"].clone(),
        subdomain_policy: parsed.get("sp").cloned(),
        percentage,
        tags: parsed,
        sender_alignment_verified: false,
        external_report_authorization_verified: false,
    })
}
