use serde_json::{Value, json};
use zixcel_domain::{
    Error, Result,
    transport::{ReadTransport, WriteTransport},
    valuedomain_edit::{self as vd, Change, Namespace},
};
struct Fake {
    text: String,
    writes: usize,
    paths: Vec<String>,
    uncertain: bool,
    namespace: Namespace,
}
impl ReadTransport for Fake {
    fn get(&mut self, path: &str) -> Result<Value> {
        self.paths.push(path.into());
        Ok(if path == "/domains?limit=50&page=1" {
            json!({"paging":{"max":1,"page":1,"limit":50},"results":[{"domainname":"example.test"}]})
        } else {
            assert_eq!(
                path,
                if self.namespace == Namespace::Registered {
                    "/domains/example.test/dns"
                } else {
                    "/freedns/example.test"
                }
            );
            json!({"results":{"domainname":"example.test","records":self.text,"ttl":3600,"ns_type":"valuedomain1"}})
        })
    }
}
impl WriteTransport for Fake {
    fn post(&mut self, _: &str, _: &Value) -> Result<Value> {
        panic!("unexpected POST")
    }
    fn put(&mut self, path: &str, body: &Value) -> Result<Value> {
        assert_eq!(
            path,
            if self.namespace == Namespace::Registered {
                "/domains/example.test/dns"
            } else {
                "/freedns/example.test"
            }
        );
        assert_eq!(
            body.get("ns_type").is_some(),
            self.namespace == Namespace::Registered
        );
        assert_eq!(body["ttl"], 3600);
        self.writes += 1;
        self.text = body["records"].as_str().unwrap().into();
        if self.uncertain {
            Err(Error::new("write_outcome_unknown"))
        } else {
            Ok(json!({"results":{}}))
        }
    }
}
fn fake(ns: Namespace) -> Fake {
    Fake {
        text: "# retain comment\na @ 192.0.2.1\ntxt @ \"v=spf1 -all\"\n".into(),
        writes: 0,
        paths: vec![],
        uncertain: false,
        namespace: ns,
    }
}
fn change() -> Change {
    Change {
        add: vec!["txt _dmarc \"v=DMARC1; p=none\"".into()],
        remove: vec![],
    }
}
#[test]
fn registered_and_freedns_never_fallback_and_preserve_unselected_bytes() {
    for ns in [Namespace::Registered, Namespace::Free] {
        let mut t = fake(ns.clone());
        let original = t.text.clone();
        let p = vd::plan(&mut t, "example.test", ns, change()).unwrap();
        assert_eq!(
            p.after.records,
            format!("{original}txt _dmarc \"v=DMARC1; p=none\"\n")
        );
        let receipt = vd::apply(&p, &mut t).unwrap();
        assert_eq!(receipt["status"], "provider_verified");
        assert_eq!(t.writes, 1);
    }
}
#[test]
fn drift_expiry_and_duplicate_spf_never_write() {
    let mut t = fake(Namespace::Registered);
    let mut p = vd::plan(&mut t, "example.test", Namespace::Registered, change()).unwrap();
    t.text.push_str("a www 192.0.2.2\n");
    assert_eq!(vd::apply(&p, &mut t).unwrap_err().code, "snapshot_drift");
    assert_eq!(t.writes, 0);
    p.expires_at = 0;
    t.paths.clear();
    assert!(vd::apply(&p, &mut t).is_err());
    assert!(t.paths.is_empty());
    let duplicate = Change {
        add: vec!["txt @ \"v=spf1 include:example.test -all\"".into()],
        remove: vec![],
    };
    assert_eq!(
        vd::plan(&mut t, "example.test", Namespace::Registered, duplicate)
            .unwrap_err()
            .code,
        "duplicate_spf"
    );
}
#[test]
fn lost_write_response_is_unknown_even_when_provider_changed() {
    let mut t = fake(Namespace::Registered);
    let p = vd::plan(&mut t, "example.test", Namespace::Registered, change()).unwrap();
    t.uncertain = true;
    assert_eq!(vd::apply(&p, &mut t).unwrap()["status"], "outcome_unknown");
    assert_eq!(t.writes, 1);
}
#[test]
fn unknown_directives_are_preserved_on_removal_and_block_unsafe_additions() {
    let mut t = fake(Namespace::Free);
    t.text.push_str("unknown untouched bytes\n");
    assert_eq!(
        vd::plan(&mut t, "example.test", Namespace::Free, change())
            .unwrap_err()
            .code,
        "unknown_source_syntax_blocks_addition"
    );
    let p = vd::plan(
        &mut t,
        "example.test",
        Namespace::Free,
        Change {
            add: vec![],
            remove: vec!["a @ 192.0.2.1".into()],
        },
    )
    .unwrap();
    assert!(p.after.records.ends_with("unknown untouched bytes\n"));
}
#[test]
fn cname_collision_and_ambiguous_removal_refuse() {
    let mut t = fake(Namespace::Registered);
    let c = Change {
        add: vec!["cname @ example.net".into()],
        remove: vec![],
    };
    assert!(vd::plan(&mut t, "example.test", Namespace::Registered, c).is_err());
    t.text.push_str("a @ 192.0.2.1\n");
    let c = Change {
        add: vec![],
        remove: vec!["a @ 192.0.2.1".into()],
    };
    assert!(vd::plan(&mut t, "example.test", Namespace::Registered, c).is_err());
}

#[test]
fn crlf_source_removes_selected_line_without_normalizing_unselected_bytes() {
    let mut t = fake(Namespace::Registered);
    t.text = "a @ 192.0.2.1\r\ntxt @ \"v=spf1 -all\"\r\n".into();
    let p = vd::plan(
        &mut t,
        "example.test",
        Namespace::Registered,
        Change {
            add: vec![],
            remove: vec!["a @ 192.0.2.1".into()],
        },
    )
    .unwrap();
    assert_eq!(p.after.records, "txt @ \"v=spf1 -all\"\r\n");
}
