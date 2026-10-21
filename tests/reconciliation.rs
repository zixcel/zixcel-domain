use serde_json::{Value, json};
use zixcel_cloudflare_observer::{ReadError, Scope, Transport, ZoneScope};
use zixcel_domain::reconciliation::{Bundle, review};
const NOW: u64 = 1_700_000_000;
struct Vendor {
    denied: bool,
}
impl Transport for Vendor {
    fn get(&mut self, path: &str) -> Result<Value, ReadError> {
        if self.denied && path.contains("/dnssec") {
            return Err(ReadError::Http(403));
        }
        let zone = json!({"id":"b".repeat(32),"name":"example.org","account":{"id":"a".repeat(32)},"name_servers":["ns1.example.net"],"status":"active"});
        let result = if path == format!("/zones/{}", "b".repeat(32)) {
            zone.clone()
        } else if path.ends_with("/dnssec") {
            json!({"status":"active","ds":format!("1 13 2 {}","A".repeat(64))})
        } else if path.ends_with("/securitytxt") {
            json!({"enabled":false})
        } else if path.ends_with("/bot_management") {
            json!({"fight_mode":false,"crawler_protection":"disabled"})
        } else if path.contains("/settings/") {
            json!({"id":path.rsplit('/').next().unwrap(),"value":"on"})
        } else if path.contains("dns_records") {
            json!([{"id":"c".repeat(32),"name":"_dmarc.example.org","type":"TXT","content":"v=DMARC1; p=none"}])
        } else if path.starts_with("/zones?") {
            json!([zone])
        } else {
            json!([])
        };
        let count = result.as_array().map(Vec::len).unwrap_or(0);
        Ok(
            json!({"success":true,"result":result,"result_info":{"page":1,"per_page":100,"total_count":count}}),
        )
    }
}
fn bundle(denied: bool) -> Bundle {
    let cf = zixcel_cloudflare_observer::observe(
        &mut Vendor { denied },
        Scope {
            account: "a".repeat(32),
            zone: Some(ZoneScope {
                id: "b".repeat(32),
                domain: "example.org".into(),
            }),
            workers: vec![],
        },
        NOW,
    )
    .unwrap();
    let dns = json!({"schema":"zix-domain-dns-audit/v1","domain":"example.org","observed_at":NOW,"writes_performed":false,
        "observations":{"dmarc_policy":{"state":"supported","data":{"tags":{"v":"DMARC1","p":"none"}}},
        "authority":{"state":"supported","data":{"delegated_nameservers":["ns1.example.net"],"parent_ds":{"state":"supported","records":[format!("1 13 2 {}","A".repeat(64))]}}}}});
    Bundle {
        cloudflare: cf,
        dns,
        registrar: None,
    }
}
fn codes(value: &Value) -> Vec<&str> {
    value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["code"].as_str())
        .collect()
}
#[test]
fn real_vendor_decoder_flows_into_cross_source_review_without_enabling_controls() {
    let result = review(&bundle(false), NOW).unwrap();
    let codes = codes(&result);
    for code in [
        "securitytxt_contact_intake_required",
        "bot_fight_mode_applicability_review",
        "ai_labyrinth_applicability_review",
        "turnstile_intake_applicability_review",
    ] {
        assert!(codes.contains(&code));
    }
    assert!(!codes.contains(&"dnssec_parent_ds_mismatch"));
    assert!(!codes.contains(&"configured_public_dmarc_drift"));
    assert_eq!(result["executable"], false);
    assert_eq!(result["approval_required"], true);
}
#[test]
fn mismatched_delegation_ds_and_policy_have_separate_findings() {
    let mut b = bundle(false);
    b.dns["observations"]["authority"]["data"]["delegated_nameservers"] =
        json!(["ns2.example.net"]);
    b.dns["observations"]["authority"]["data"]["parent_ds"]["records"] = json!([]);
    b.dns["observations"]["dmarc_policy"]["data"]["tags"]["p"] = json!("reject");
    let result = review(&b, NOW).unwrap();
    let c = codes(&result);
    for code in [
        "cloudflare_delegation_mismatch",
        "dnssec_parent_ds_missing",
        "configured_public_dmarc_drift",
    ] {
        assert!(c.contains(&code));
    }
}
#[test]
fn denied_dnssec_does_not_become_an_inactive_signer_finding() {
    let result = review(&bundle(true), NOW).unwrap();
    assert!(!codes(&result).iter().any(|c| c.starts_with("dnssec_")));
    assert_eq!(result["cloudflare_states"]["dnssec"], "denied");
}
#[test]
fn stale_tampered_and_cross_zone_inputs_are_refused() {
    let mut b = bundle(false);
    assert!(review(&b, NOW + 3601).is_err());
    b.dns["domain"] = json!("other.org");
    assert!(review(&b, NOW).is_err());
    let mut b = bundle(false);
    b.cloudflare.observations.remove("dns_records");
    assert!(review(&b, NOW).is_err());
}
