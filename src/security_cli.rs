//! Standalone CLI glue. Credentials and DNS writes are not accepted by these commands.
use crate::{Result, error, transport::HttpTransport};
use serde_json::Value;
use std::io::Read;
pub fn run(args: &[String]) -> Option<Result<Value>> {
    match args {
        [command] if command == "dns-security-review" => Some((|| {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| error("input_unavailable"))?;
            if bytes.len() > 1024 * 1024 {
                return Err(error("input_budget"));
            }
            let bundle = serde_json::from_slice(&bytes)
                .map_err(|_| error("invalid_reconciliation_bundle"))?;
            crate::reconciliation::review(&bundle, crate::approval::now()?)
        })()),
        [command, domain] if command == "dns-security-audit" => Some(public(domain, false)),
        [command, domain, flag] if command == "dns-security-audit" && flag == "--authority" => {
            Some(public(domain, true))
        }
        [command, domain] if command == "securitytxt-preview" => Some((|| {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(32769)
                .read_to_end(&mut bytes)
                .map_err(|_| error("input_unavailable"))?;
            if bytes.len() > 32768 {
                return Err(error("securitytxt_budget"));
            }
            crate::security_txt::inspect(
                std::str::from_utf8(&bytes).map_err(|_| error("invalid_utf8"))?,
                domain,
                crate::approval::now()?,
            )
        })()),
        _ => None,
    }
}
fn public(domain: &str, authority: bool) -> Result<Value> {
    let domain = crate::domain_name(domain)?;
    let mut http = HttpTransport::public_dns()?;
    http.limit_time(std::time::Duration::from_secs(40))?;
    crate::dns_audit::observe(&mut http, &domain, crate::approval::now()?, authority)
}
