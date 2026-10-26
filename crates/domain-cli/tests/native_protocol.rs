use serde_json::{Value, json};
use zix_native_provider::Request;
use zixcel_domain::{Result, transport::ReadTransport};
use zixcel_domain_cli as native;
fn request() -> Request {
    request_for(&std::env::current_exe().unwrap())
}
fn request_for(path: &std::path::Path) -> Request {
    let binding = zix_operation_contracts::Binding::for_catalog(
        "zixcel-domain-cli",
        env!("CARGO_PKG_VERSION"),
        &serde_json::to_value(native::manifest()).unwrap(),
        &zix_cli::files::digest(&std::fs::read(path).unwrap()),
    );
    serde_json::from_value(json!({"schema":"zix-provider/v1","id":"0".repeat(32),"operation":"valuedomain.domains.list",
    "arguments":{},"binding":binding,"limits":{"timeout_ms":5000,"maximum_response_bytes":65536}})).unwrap()
}
struct Fake {
    paths: Vec<String>,
}
impl ReadTransport for Fake {
    fn get(&mut self, path: &str) -> Result<Value> {
        self.paths.push(path.into());
        Ok(match path {
            "/domains?limit=50&page=1" => {
                json!({"paging":{"max":2,"page":1,"limit":50},"results":[{"domainname":"enabled.example.invalid"},{"domainname":"disabled.example.invalid"}]})
            }
            "/domains/enabled.example.invalid/autorenew" => {
                json!({"domainname":"enabled.example.invalid","results":{"domainname":"enabled.example.invalid","autorenew_domain":10}})
            }
            "/domains/disabled.example.invalid/autorenew" => {
                json!({"domainname":"disabled.example.invalid","results":{"domainname":"disabled.example.invalid","autorenew_domain":9}})
            }
            _ => panic!("unreviewed path"),
        })
    }
}
#[test]
fn native_adapter_reuses_domain_pagination_and_renewal_filter_without_writes() {
    let mut port = Fake { paths: vec![] };
    let mut req = request();
    req.arguments
        .insert("exclude-auto-renew-disabled".into(), "true".into());
    let result = native::observe(&req, &mut port).unwrap();
    assert_eq!(result["domains"].as_array().unwrap().len(), 1);
    assert_eq!(result["domains"][0]["domain"], "enabled.example.invalid");
    assert_eq!(result["writes_performed"], false);
    assert_eq!(port.paths.len(), 3);
}
#[test]
fn unknown_mutations_and_filter_values_never_reach_existing_transport() {
    let mut port = Fake { paths: vec![] };
    let mut req = request();
    req.operation = "dns.delete".into();
    assert!(native::observe(&req, &mut port).is_err());
    let mut req = request();
    req.arguments
        .insert("exclude-auto-renew-disabled".into(), "other".into());
    assert!(native::observe(&req, &mut port).is_err());
    assert!(port.paths.is_empty());
}
#[test]
fn native_binary_has_no_ambient_credential_fallback_or_node_requirement() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let manifest = Command::new(env!("CARGO_BIN_EXE_zix-domain"))
        .env_clear()
        .arg("--manifest")
        .output()
        .unwrap();
    assert!(manifest.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&manifest.stdout).unwrap()["namespace"],
        "domain"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_zix-domain"))
        .env_clear()
        .arg("--zix-provider-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            &serde_json::to_vec(&request_for(std::path::Path::new(env!(
                "CARGO_BIN_EXE_zix-domain"
            ))))
            .unwrap(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["error"],
        "credential_missing"
    );
}
