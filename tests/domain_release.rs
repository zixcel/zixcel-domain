use serde_json::{Value, json};
use zixcel_domain::{
    Error, Result,
    domain_release::{Session, source},
    transport::{ReadTransport, WriteTransport},
    valuedomain,
};
const ACCOUNT: &str = "00000000000000000000000000000001";
const ZONE: &str = "00000000000000000000000000000002";
struct Registrar {
    ns: Vec<String>,
    records: String,
    puts: usize,
    dns_type: String,
    free_reads: usize,
}
impl Registrar {
    fn new() -> Self {
        Self {
            ns: vec![
                "ns11.value-domain.com".into(),
                "ns12.value-domain.com".into(),
            ],
            records: "a @ 203.0.113.1\nmx mail.example.test 10\ntxt @ \"v=spf1 -all\"".into(),
            puts: 0,
            dns_type: "valuedomain11".into(),
            free_reads: 0,
        }
    }
}
impl ReadTransport for Registrar {
    fn get(&mut self, path: &str) -> Result<Value> {
        match path {
            "/domains?limit=50&page=1" => Ok(
                json!({"paging":{"max":1,"limit":50,"page":1},"results":[{"domainname":"example.test"}]}),
            ),
            "/domains/example.test/nameserver" => {
                Ok(json!({"results":{"domainname":"example.test","ns":self.ns}}))
            }
            "/domains/example.test/dns" => Ok(
                json!({"results":{"domainname":"example.test","records":self.records,"ttl":"3600","ns_type":self.dns_type}}),
            ),
            "/freedns/example.test" => {
                self.free_reads += 1;
                Ok(
                    json!({"results":{"domainname":"example.test","records":self.records,"ttl":"3600"}}),
                )
            }
            _ => Err(Error::new("unexpected_fixture_request")),
        }
    }
}
impl WriteTransport for Registrar {
    fn post(&mut self, _: &str, _: &Value) -> Result<Value> {
        panic!("unexpected registrar POST")
    }
    fn put(&mut self, path: &str, body: &Value) -> Result<Value> {
        assert_eq!(path, "/domains/example.test/nameserver");
        self.puts += 1;
        self.ns = body["ns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect();
        Ok(json!({"results":{"domainname":"example.test","ns":self.ns}}))
    }
}
struct Dns {
    present: bool,
    records: Vec<Value>,
    posts: usize,
    fail_record: bool,
}
impl Dns {
    fn new() -> Self {
        Self {
            present: false,
            records: vec![],
            posts: 0,
            fail_record: false,
        }
    }
}
impl ReadTransport for Dns {
    fn get(&mut self, path: &str) -> Result<Value> {
        if path.starts_with("/zones?") {
            assert!(path.contains(ACCOUNT));
            let records = if self.present {
                vec![
                    json!({"id":ZONE,"account":{"id":ACCOUNT},"name":"example.test","status":"pending","name_servers":["arya.ns.cloudflare.com","david.ns.cloudflare.com"]}),
                ]
            } else {
                vec![]
            };
            Ok(
                json!({"success":true,"result_info":{"page":1,"total_count":records.len()},"result":records}),
            )
        } else if path.starts_with(&format!("/zones/{ZONE}/dns_records?")) {
            Ok(
                json!({"success":true,"result_info":{"page":1,"total_count":self.records.len()},"result":self.records}),
            )
        } else {
            Err(Error::new("unexpected_fixture_request"))
        }
    }
}
impl WriteTransport for Dns {
    fn post(&mut self, path: &str, body: &Value) -> Result<Value> {
        self.posts += 1;
        if path == "/zones" {
            self.present = true;
            Ok(json!({"success":true,"result":{"name":"example.test","account":{"id":ACCOUNT}}}))
        } else {
            assert_eq!(path, format!("/zones/{ZONE}/dns_records"));
            if self.fail_record {
                return Err(Error::new("write_outcome_unknown"));
            }
            let mut record = body.clone();
            record["id"] = json!(format!("{:032x}", self.records.len() + 10));
            self.records.push(record.clone());
            Ok(json!({"success":true,"result":record}))
        }
    }
    fn put(&mut self, _: &str, _: &Value) -> Result<Value> {
        panic!("no record overwrites allowed")
    }
}
struct Public {
    ds: bool,
    delegated_11: bool,
}
impl ReadTransport for Public {
    fn delegation(&mut self, _: &str) -> Result<Vec<String>> {
        Ok(vec![
            if self.delegated_11 {
                "ns11.value-domain.com"
            } else {
                "ns1.value-domain.com"
            }
            .into(),
        ])
    }
    fn get(&mut self, path: &str) -> Result<Value> {
        let kind = path.rsplit('=').next().unwrap();
        let (number, data) = match kind {
            "NS" => (2, vec!["ns1.value-domain.com."]),
            "SOA" => (
                6,
                vec!["ns1.value-domain.com. hostmaster.example.test. 1 3600 900 604800 3600"],
            ),
            "DS" => (
                43,
                if self.ds {
                    vec!["1 1 1 deadbeef"]
                } else {
                    vec![]
                },
            ),
            "MX" => (15, vec!["10 mail.example.test."]),
            "TXT" => (16, vec!["\"v=spf1 -all\""]),
            _ => panic!("unknown query"),
        };
        Ok(
            json!({"Status":0,"TC":false,"Question":[{"name":"example.test.","type":number}],"Answer":data.into_iter().map(|s|json!({"name":"example.test.","type":number,"TTL":3600,"data":s})).collect::<Vec<_>>()}),
        )
    }
}
fn planned(
    session: &mut Session,
    phase: &str,
    r: &mut Registrar,
    d: &mut Dns,
    p: &mut Public,
) -> String {
    session.plan(phase, r, d, p).unwrap()["sha256"]
        .as_str()
        .unwrap()
        .into()
}
#[test]
fn free_dns_uses_authoritative_service_and_accepts_documented_string_ttl() {
    let mut r = Registrar::new();
    let mut p = Public {
        ds: false,
        delegated_11: false,
    };
    let s = source(&mut r, &mut p, "example.test").unwrap();
    assert_eq!(s.dns_service, "valuedomain1");
    assert_eq!(s.ttl, 3600);
    assert_ne!(s.public_nameservers, s.registrar_nameservers);
    assert_eq!(
        valuedomain::free_dns(&mut r, "example.test")
            .unwrap()
            .ns_type,
        "valuedomain1"
    );
}
#[test]
fn plans_preserve_mail_exclude_web_apex_and_bind_one_use_approval() {
    let (mut r, mut d, mut p) = (
        Registrar::new(),
        Dns::new(),
        Public {
            ds: false,
            delegated_11: false,
        },
    );
    let mut s = Session::new("example.test", ACCOUNT).unwrap();
    let hash = planned(&mut s, "prepare_zone", &mut r, &mut d, &mut p);
    let receipt = s.apply(&hash, &mut r, &mut d, &mut p).unwrap();
    assert_eq!(receipt["status"], "provider_verified");
    assert_eq!(d.records.len(), 2);
    assert_eq!(d.posts, 3);
    assert_eq!(r.puts, 0);
    assert!(d.records.iter().all(|r| r["type"] != "A"));
    assert_eq!(
        s.apply(&hash, &mut r, &mut d, &mut p).unwrap_err().code,
        "unissued_or_consumed_plan"
    );
    assert_eq!(d.posts, 3);
    assert_eq!(
        s.apply(&"f".repeat(64), &mut r, &mut d, &mut p)
            .unwrap_err()
            .code,
        "unissued_or_consumed_plan"
    );
    let mut other = Session::new("example.test", ACCOUNT).unwrap();
    assert_eq!(
        other.apply(&hash, &mut r, &mut d, &mut p).unwrap_err().code,
        "unissued_or_consumed_plan"
    );
}
#[test]
fn snapshot_drift_consumes_approval_without_writes() {
    let (mut r, mut d, mut p) = (
        Registrar::new(),
        Dns::new(),
        Public {
            ds: false,
            delegated_11: false,
        },
    );
    let mut s = Session::new("example.test", ACCOUNT).unwrap();
    let hash = planned(&mut s, "prepare_zone", &mut r, &mut d, &mut p);
    r.records.push_str("\ntxt extra \"changed\"");
    assert_eq!(
        s.apply(&hash, &mut r, &mut d, &mut p).unwrap_err().code,
        "snapshot_drift"
    );
    assert_eq!(d.posts, 0);
    assert_eq!(r.puts, 0);
}
#[test]
fn uncertain_record_write_is_not_retried_or_reported_applied() {
    let (mut r, mut d, mut p) = (
        Registrar::new(),
        Dns::new(),
        Public {
            ds: false,
            delegated_11: false,
        },
    );
    let mut s = Session::new("example.test", ACCOUNT).unwrap();
    let hash = planned(&mut s, "prepare_zone", &mut r, &mut d, &mut p);
    d.fail_record = true;
    let result = s.apply(&hash, &mut r, &mut d, &mut p).unwrap();
    assert_eq!(result["status"], "partial_or_unknown");
    assert_eq!(d.posts, 2);
    assert_eq!(r.puts, 0);
    assert_eq!(
        s.apply(&hash, &mut r, &mut d, &mut p).unwrap_err().code,
        "unissued_or_consumed_plan"
    );
    assert_eq!(d.posts, 2);
}
#[test]
fn nameserver_switch_requires_verified_copy_and_absent_ds() {
    let (mut r, mut d, mut p) = (
        Registrar::new(),
        Dns::new(),
        Public {
            ds: false,
            delegated_11: false,
        },
    );
    let mut s = Session::new("example.test", ACCOUNT).unwrap();
    assert_eq!(
        s.plan("change_nameservers", &mut r, &mut d, &mut p)
            .unwrap_err()
            .code,
        "zone_not_prepared"
    );
    let hash = planned(&mut s, "prepare_zone", &mut r, &mut d, &mut p);
    s.apply(&hash, &mut r, &mut d, &mut p).unwrap();
    p.ds = true;
    assert_eq!(
        s.plan("change_nameservers", &mut r, &mut d, &mut p)
            .unwrap_err()
            .code,
        "dnssec_transition_required"
    );
    assert_eq!(r.puts, 0);
    p.ds = false;
    let hash = planned(&mut s, "change_nameservers", &mut r, &mut d, &mut p);
    let result = s.apply(&hash, &mut r, &mut d, &mut p).unwrap();
    assert_eq!(r.puts, 1);
    assert_eq!(result["status"], "provider_verified");
    assert_eq!(
        result["result"]["public_propagation"],
        "pending_separate_verification"
    );
    let hash = planned(&mut s, "change_nameservers", &mut r, &mut d, &mut p);
    s.apply(&hash, &mut r, &mut d, &mut p).unwrap();
    assert_eq!(r.puts, 1);
}
#[test]
fn self_targeted_mail_and_incompatible_records_are_rejected() {
    let (mut r, mut d, mut p) = (
        Registrar::new(),
        Dns::new(),
        Public {
            ds: false,
            delegated_11: false,
        },
    );
    let mut s = Session::new("example.test", ACCOUNT).unwrap();
    r.records = "a @ 203.0.113.1\nmx @ 10".into();
    assert_eq!(
        s.plan("prepare_zone", &mut r, &mut d, &mut p)
            .unwrap_err()
            .code,
        "mail_depends_on_web_apex"
    );
    assert_eq!(d.posts, 0);
}

#[test]
fn public_mail_records_missing_from_export_block_zone_preparation() {
    let (mut registrar, mut dns, mut public) = (
        Registrar::new(),
        Dns::new(),
        Public {
            ds: false,
            delegated_11: false,
        },
    );
    registrar.records = "a @ 203.0.113.1\ntxt @ \"v=spf1 -all\"".into();
    let mut session = Session::new("example.test", ACCOUNT).unwrap();
    assert_eq!(
        session
            .plan("prepare_zone", &mut registrar, &mut dns, &mut public)
            .unwrap_err()
            .code,
        "public_mail_export_mismatch"
    );
    assert_eq!(dns.posts, 0);
    assert_eq!(registrar.puts, 0);
}

#[test]
fn parent_delegation_selects_registered_dns_despite_stale_child_ns_and_soa() {
    let mut r = Registrar::new();
    let mut p = Public {
        ds: false,
        delegated_11: true,
    };
    let s = source(&mut r, &mut p, "example.test").unwrap();
    assert_eq!(s.dns_service, "valuedomain11");
    assert_ne!(s.parent_delegation_nameservers, s.public_nameservers);
    assert!(s.public_soa.starts_with("ns1.value-domain.com."));
    assert_eq!(r.free_reads, 0);
}

#[test]
fn registered_ns1_domain_does_not_need_membership_in_separate_freedns_inventory() {
    let mut r = Registrar::new();
    r.dns_type = "valuedomain1".into();
    let mut p = Public {
        ds: false,
        delegated_11: false,
    };
    assert_eq!(
        source(&mut r, &mut p, "example.test").unwrap().dns_service,
        "valuedomain1"
    );
    assert_eq!(r.free_reads, 0);
}

#[test]
fn parent_delegation_drift_consumes_plan_before_cloudflare_writes() {
    let (mut r, mut d, mut p) = (
        Registrar::new(),
        Dns::new(),
        Public {
            ds: false,
            delegated_11: false,
        },
    );
    let mut session = Session::new("example.test", ACCOUNT).unwrap();
    let hash = planned(&mut session, "prepare_zone", &mut r, &mut d, &mut p);
    p.delegated_11 = true;
    assert!(session.apply(&hash, &mut r, &mut d, &mut p).is_err());
    assert_eq!(d.posts, 0);
    assert!(session.apply(&hash, &mut r, &mut d, &mut p).is_err());
}

struct UnservedPublic {
    legacy: bool,
    ds: bool,
    mixed: bool,
}
impl ReadTransport for UnservedPublic {
    fn delegation(&mut self, _: &str) -> Result<Vec<String>> {
        if self.mixed {
            return Ok(vec!["ns11.value-domain.com".into(), "outside.test".into()]);
        }
        if self.legacy {
            return Ok((1..=5).map(|n| format!("ns{n}.value-domain.com")).collect());
        }
        Ok([11, 12, 13]
            .map(|n| format!("ns{n}.value-domain.com"))
            .to_vec())
    }
    fn get(&mut self, path: &str) -> Result<Value> {
        if !path.ends_with("type=DS") {
            return Ok(json!({"Status":2}));
        }
        let answers = if self.ds {
            vec![json!({"name":"example.test.","type":43,"TTL":3600,"data":"1 1 1 deadbeef"})]
        } else {
            vec![]
        };
        Ok(
            json!({"Status":0,"TC":false,"Question":[{"name":"example.test.","type":43}],"Answer":answers}),
        )
    }
}
fn empty_fixture() -> (Registrar, Dns, UnservedPublic) {
    let mut registrar = Registrar::new();
    registrar.ns = [11, 12, 13]
        .map(|n| format!("ns{n}.value-domain.com"))
        .to_vec();
    registrar.records = String::new();
    registrar.dns_type = "valuedomain11".into();
    (
        registrar,
        Dns::new(),
        UnservedPublic {
            legacy: false,
            ds: false,
            mixed: false,
        },
    )
}
#[test]
fn unserved_dns_requires_explicit_empty_registered_policy() {
    let (mut r, mut d, mut p) = empty_fixture();
    let mut session = Session::new("example.test", ACCOUNT).unwrap();
    assert_eq!(
        session
            .plan("prepare_zone", &mut r, &mut d, &mut p)
            .unwrap_err()
            .code,
        "dns_servfail"
    );
    assert_eq!(d.posts + r.puts, 0);
}
#[test]
fn empty_registered_policy_plans_and_applies_without_claiming_public_dns_observation() {
    let (mut r, mut d, mut p) = empty_fixture();
    let mut session = Session::new("example.test", ACCOUNT)
        .unwrap()
        .allow_empty_registered_unserved();
    let plan = session
        .plan("prepare_zone", &mut r, &mut d, &mut p)
        .unwrap();
    assert_eq!(
        plan["plan"]["source"]["source_mode"],
        "empty_registered_unserved"
    );
    assert_eq!(plan["plan"]["source"]["public_soa"], "");
    let hash = plan["sha256"].as_str().unwrap();
    assert_eq!(
        session.apply(hash, &mut r, &mut d, &mut p).unwrap()["status"],
        "provider_verified"
    );
    let plan = session
        .plan("change_nameservers", &mut r, &mut d, &mut p)
        .unwrap();
    let hash = plan["sha256"].as_str().unwrap();
    let result = session.apply(hash, &mut r, &mut d, &mut p).unwrap();
    assert_eq!(result["status"], "provider_verified");
    assert_eq!(
        result["result"]["public_propagation"],
        "pending_separate_verification"
    );
    assert_eq!(r.puts, 1);
    assert_eq!(
        session
            .apply(hash, &mut r, &mut d, &mut p)
            .unwrap_err()
            .code,
        "unissued_or_consumed_plan"
    );
}
#[test]
fn empty_policy_refuses_records_dnssec_mixed_delegation_and_populated_target() {
    for case in 0..4 {
        let (mut r, mut d, mut p) = empty_fixture();
        match case {
            0 => r.records = "mx mail 10".into(),
            1 => p.ds = true,
            2 => p.mixed = true,
            _ => {
                d.present = true;
                d.records.push(
                    json!({"id":ZONE,"type":"TXT","name":"example.test","content":"existing"}),
                );
            }
        }
        let mut session = Session::new("example.test", ACCOUNT)
            .unwrap()
            .allow_empty_registered_unserved();
        assert!(
            session
                .plan("prepare_zone", &mut r, &mut d, &mut p)
                .is_err()
        );
        assert_eq!(d.posts + r.puts, 0);
    }
}
#[test]
fn empty_source_drift_consumes_plan_without_writes() {
    let (mut r, mut d, mut p) = empty_fixture();
    let mut session = Session::new("example.test", ACCOUNT)
        .unwrap()
        .allow_empty_registered_unserved();
    let plan = session
        .plan("prepare_zone", &mut r, &mut d, &mut p)
        .unwrap();
    r.records = "txt changed".into();
    let hash = plan["sha256"].as_str().unwrap();
    assert!(session.apply(hash, &mut r, &mut d, &mut p).is_err());
    assert_eq!(d.posts + r.puts, 0);
    assert_eq!(
        session
            .apply(hash, &mut r, &mut d, &mut p)
            .unwrap_err()
            .code,
        "unissued_or_consumed_plan"
    );
}

#[test]
fn empty_valuedomain1_requires_matching_full_delegation_and_stored_service() {
    for mismatch in [false, true] {
        let (mut r, mut d, mut p) = empty_fixture();
        r.ns = (1..=5).map(|n| format!("ns{n}.value-domain.com")).collect();
        p.legacy = true;
        r.dns_type = if mismatch {
            "valuedomain11"
        } else {
            "valuedomain1"
        }
        .into();
        let mut session = Session::new("example.test", ACCOUNT)
            .unwrap()
            .allow_empty_registered_unserved();
        let plan = session.plan("prepare_zone", &mut r, &mut d, &mut p);
        if mismatch {
            assert!(plan.is_err());
            assert_eq!(d.posts + r.puts, 0);
        } else {
            let plan = plan.unwrap();
            assert_eq!(plan["plan"]["source"]["dns_service"], "valuedomain1");
            assert_eq!(
                session
                    .apply(plan["sha256"].as_str().unwrap(), &mut r, &mut d, &mut p)
                    .unwrap()["status"],
                "provider_verified"
            );
        }
    }
}

#[test]
fn unused_mail_retirement_is_explicit_and_preserves_unrelated_records() {
    let mut r = Registrar::new();
    r.records.push_str(
        "\nmx example.test 10\na keep 203.0.113.2\ntxt @ \"unrelated-verification=fixture\"",
    );
    let mut d = Dns::new();
    let mut p = Public {
        ds: false,
        delegated_11: false,
    };
    let mut default = Session::new("example.test", ACCOUNT).unwrap();
    assert_eq!(
        default
            .plan("prepare_zone", &mut r, &mut d, &mut p)
            .unwrap_err()
            .code,
        "mail_depends_on_web_apex"
    );
    let mut opted = Session::new("example.test", ACCOUNT)
        .unwrap()
        .retire_unused_mail();
    let plan = opted.plan("prepare_zone", &mut r, &mut d, &mut p).unwrap();
    assert_eq!(plan["plan"]["retire_unused_mail"], true);
    assert_eq!(
        plan["plan"]["records_to_retire"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        plan["plan"]["records_to_preserve"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(plan["plan"]["records_to_add"].as_array().unwrap().len(), 3);
    assert_eq!(
        opted
            .apply(plan["sha256"].as_str().unwrap(), &mut r, &mut d, &mut p)
            .unwrap()["status"],
        "provider_verified"
    );
    assert!(
        d.records
            .iter()
            .any(|r| r["type"] == "MX" && r["content"] == "." && r["priority"] == 0)
    );
    assert!(d.records.iter().any(|r| r["content"] == "\"v=spf1 -all\""));
    assert!(
        !d.records
            .iter()
            .any(|r| r["type"] == "MX" && r["content"] != ".")
    );
    let plan = opted
        .plan("change_nameservers", &mut r, &mut d, &mut p)
        .unwrap();
    assert_eq!(
        opted
            .apply(plan["sha256"].as_str().unwrap(), &mut r, &mut d, &mut p)
            .unwrap()["status"],
        "provider_verified"
    );
}
#[test]
fn unused_mail_policy_never_overwrites_existing_target_mail() {
    let mut r = Registrar::new();
    let mut d = Dns::new();
    d.present = true;
    d.records.push(json!({"id":ZONE,"type":"MX","name":"example.test","content":"existing.test","priority":10,"ttl":3600,"proxied":false}));
    let mut p = Public {
        ds: false,
        delegated_11: false,
    };
    let mut s = Session::new("example.test", ACCOUNT)
        .unwrap()
        .retire_unused_mail();
    assert_eq!(
        s.plan("prepare_zone", &mut r, &mut d, &mut p)
            .unwrap_err()
            .code,
        "target_mail_retirement_requires_review"
    );
    assert_eq!(d.posts + r.puts, 0);
}

#[test]
fn plan_digest_has_stable_lowercase_hex_bytes_across_digest_versions() {
    assert_eq!(
        zixcel_domain::domain_release::digest(&json!({"fixture":"one-use-plan","revision":1}))
            .unwrap(),
        "bc5ba0430d0027e94b5ecbe0354e46d3356f0b074c16c639f9fbbe3cf89b895e"
    );
}
