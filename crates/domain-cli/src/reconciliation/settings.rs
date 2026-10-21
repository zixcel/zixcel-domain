use super::data;
use serde_json::{Value, json};
use zixcel_cloudflare_observer::Report;
use zixcel_domain::{Result, error};
pub(super) fn check(
    report: &Report,
    dns: &Value,
    domain: &str,
    out: &mut Vec<Value>,
) -> Result<()> {
    if let Some(rows) = data(report, "dns_records").and_then(Value::as_array) {
        let mut txt = Vec::new();
        for row in rows {
            let name = row["name"]
                .as_str()
                .ok_or_else(|| error("dns_record_name_missing"))?;
            if !(name == domain || name.ends_with(&format!(".{domain}"))) {
                return Err(error("cross_zone_record"));
            }
            if row["type"] == "TXT" && name == format!("_dmarc.{domain}") {
                txt.push(
                    row["content"]
                        .as_str()
                        .ok_or_else(|| error("invalid_txt"))?
                        .to_owned(),
                );
            }
        }
        match zixcel_domain::dmarc::parse(&txt) {
            Err(e) => out.push(
                json!({"code":e.code,"source":"cloudflare_dns_records","automatic_fix":false}),
            ),
            Ok(policy) => {
                let public = &dns["observations"]["dmarc_policy"];
                if public["state"] == "supported" && public["data"]["tags"] != json!(policy.tags) {
                    out.push(json!({"code":"configured_public_dmarc_drift","automatic_fix":false}));
                }
            }
        }
    }
    for (component, field, wanted, code) in [
        (
            "security_txt",
            "enabled",
            json!(false),
            "securitytxt_contact_intake_required",
        ),
        (
            "bot_management",
            "fight_mode",
            json!(false),
            "bot_fight_mode_applicability_review",
        ),
        (
            "bot_management",
            "crawler_protection",
            json!("disabled"),
            "ai_labyrinth_applicability_review",
        ),
    ] {
        if data(report, component).is_some_and(|v| v.get(field) == Some(&wanted)) {
            out.push(json!({"code":code,"automatic_enable":false,"requires_owner_review":true}));
        }
    }
    if let Some(widgets) = data(report, "turnstile_widgets").and_then(Value::as_array)
        && !widgets.iter().any(|v| {
            v["domains"]
                .as_array()
                .is_some_and(|names| names.iter().any(|n| n == domain))
        })
    {
        out.push(json!({"code":"turnstile_intake_applicability_review","automatic_enable":false,"frontend_and_server_integration_required":true}));
    }
    if let Some(sites) = data(report, "web_analytics").and_then(Value::as_array)
        && sites
            .iter()
            .any(|v| v["zone_name"] == domain && v["auto_install"] == true)
    {
        out.push(json!({"code":"analytics_html_injection_configured","actual_delivery_and_privacy_review_required":true}));
    }
    Ok(())
}
