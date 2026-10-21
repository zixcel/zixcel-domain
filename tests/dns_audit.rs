use serde_json::{Value, json};
use zixcel_domain::{Error, Result, dns_audit, transport::ReadTransport};
struct Dns {
    calls: Vec<String>,
    fail: bool,
}
impl ReadTransport for Dns {
    fn get(&mut self, path: &str) -> Result<Value> {
        self.calls.push(path.into());
        if self.fail {
            return Err(Error::new("dns_servfail"));
        }
        let query = path.split_once('?').unwrap().1;
        let mut parts = query.split('&');
        let name = parts.next().unwrap().strip_prefix("name=").unwrap();
        let kind = parts.next().unwrap().strip_prefix("type=").unwrap();
        let number = match kind {
            "TXT" => 16,
            "MX" => 15,
            "NS" => 2,
            "DS" => 43,
            "CAA" => 257,
            _ => panic!("unknown query"),
        };
        let answers = if name.starts_with("_dmarc.") {
            vec![
                json!({"name":format!("{name}."),"type":16,"TTL":300,"data":"\"v=DMARC1; p=none\""}),
            ]
        } else {
            vec![]
        };
        Ok(
            json!({"Status":0,"TC":false,"AD":false,"Question":[{"name":format!("{name}."),"type":number}],"Answer":answers}),
        )
    }
}
#[test]
fn audit_reads_actual_dmarc_owner_and_keeps_coverage_and_alignment_separate() {
    let mut dns = Dns {
        calls: vec![],
        fail: false,
    };
    let report = dns_audit::observe(&mut dns, "example.test", 1000, false).unwrap();
    assert_eq!(dns.calls.len(), 6);
    assert!(dns.calls[0].contains("name=_dmarc.example.test"));
    assert_eq!(
        report["observations"]["dmarc_policy"]["data"]["policy"],
        "none"
    );
    assert_eq!(report["zone_inventory_complete"], false);
    assert_eq!(report["mail_alignment"], "unobserved");
    assert!(dns_audit::validate_report(&report, "example.test", 1001).is_ok());
    assert!(dns_audit::validate_report(&report, "wrong.test", 1001).is_err());
    assert!(dns_audit::validate_report(&report, "example.test", 5000).is_err());
}
#[test]
fn failed_reads_do_not_become_missing_policy_or_a_safe_domain() {
    let report = dns_audit::observe(
        &mut Dns {
            calls: vec![],
            fail: true,
        },
        "example.test",
        1000,
        true,
    )
    .unwrap();
    assert_eq!(report["observations"]["dmarc"]["state"], "unobserved");
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["observations"]["authority"]["state"], "unobserved");
}
