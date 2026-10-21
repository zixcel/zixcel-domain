use super::data;
use serde_json::{Value, json};
use zixcel_cloudflare_observer::Report;
use zixcel_domain::{Result, error};
fn ds(value: &str) -> Result<String> {
    let fields: Vec<_> = value.split_whitespace().collect();
    if fields.len() != 4
        || fields[0].parse::<u16>().is_err()
        || fields[1].parse::<u8>().is_err()
        || fields[2].parse::<u8>().is_err()
        || fields[3].is_empty()
        || fields[3].len() > 128
        || !fields[3].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(error("invalid_ds_evidence"));
    }
    let len = match fields[2] {
        "1" => 40,
        "2" => 64,
        "4" => 96,
        _ => return Err(error("unsupported_ds_digest")),
    };
    if fields[3].len() != len {
        return Err(error("invalid_ds_evidence"));
    }
    Ok(format!(
        "{} {} {} {}",
        fields[0],
        fields[1],
        fields[2],
        fields[3].to_ascii_uppercase()
    ))
}
pub(super) fn check(report: &Report, dns: &Value, out: &mut Vec<Value>) -> Result<()> {
    let Some(config) = data(report, "dnssec") else {
        return Ok(());
    };
    let authority = &dns["observations"]["authority"];
    let parent = &authority["data"]["parent_ds"];
    if authority["state"] != "supported" || parent["state"] != "supported" {
        return Ok(());
    }
    let rows = parent["records"]
        .as_array()
        .ok_or_else(|| error("invalid_parent_ds"))?;
    if rows.len() > 16 {
        return Err(error("parent_ds_budget"));
    }
    let records = rows
        .iter()
        .map(|v| ds(v.as_str().ok_or_else(|| error("invalid_parent_ds"))?))
        .collect::<Result<Vec<_>>>()?;
    let code = match config["status"].as_str() {
        Some("active") if records.is_empty() => Some("dnssec_parent_ds_missing"),
        Some("active") => {
            let expected = ds(config["ds"]
                .as_str()
                .ok_or_else(|| error("cloudflare_ds_unobserved"))?)?;
            (!records.contains(&expected)).then_some("dnssec_parent_ds_mismatch")
        }
        Some("disabled") if !records.is_empty() => Some("dnssec_parent_ds_without_active_signing"),
        _ => None,
    };
    if let Some(code) = code {
        out.push(json!({"code":code,"severity":"error","automatic_fix":false,"requires_dnssec_rollover_review":true}));
    }
    Ok(())
}
