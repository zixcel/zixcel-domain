use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zix_native_provider::{Error, Failure, Request, validate_request};
use zixcel_domain::{
    transport::{HttpTransport, Provider, ReadTransport},
    valuedomain,
};
fn failure(e: zixcel_domain::Error) -> Failure {
    Failure {
        code: e.code,
        http_status: e.http_status,
    }
}
pub fn execute(request: &Request) -> Result<Value, Failure> {
    validate_request(&crate::manifest(), request)?;
    if request.operation == "valuedomain.domains.list" {
        return crate::registrar::execute(request);
    }
    if request.operation == "dns.reconcile" {
        let path = request
            .arguments
            .get("report")
            .ok_or(Error("argument_missing"))?;
        let bytes = zix_cli::files::read(std::path::Path::new(path), 1024 * 1024, false)?;
        let bundle =
            serde_json::from_slice(&bytes).map_err(|_| Error("invalid_reconciliation_bundle"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error("clock_unavailable"))?
            .as_secs();
        return zixcel_domain::reconciliation::review(&bundle, now).map_err(failure);
    }
    let domain = zixcel_domain::domain_name(
        request
            .arguments
            .get("domain")
            .ok_or(Error("argument_missing"))?,
    )
    .map_err(failure)?;
    let timeout = Duration::from_millis(request.limits.timeout_ms.saturating_sub(20).max(50));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error("clock_unavailable"))?
        .as_secs();
    if request.operation == "dns.audit" {
        let authority = match request.arguments.get("authority").map(String::as_str) {
            None | Some("false") => false,
            Some("true") => true,
            _ => return Err(Error("invalid_authority_flag").into()),
        };
        let mut http = HttpTransport::public_dns().map_err(failure)?;
        http.limit_time(timeout).map_err(failure)?;
        return zixcel_domain::dns_audit::observe(&mut http, &domain, now, authority)
            .map_err(failure);
    }
    if request.operation != "registrar.inspect" {
        return Err(Error("unknown_operation").into());
    }
    let mut http = HttpTransport::from_env(Provider::ValueDomain, "ZIX_VALUEDOMAIN_ACCESS_TOKEN")
        .map_err(failure)?;
    http.limit_time(timeout).map_err(failure)?;
    let entries = valuedomain::domains(&mut http).map_err(failure)?;
    let selected = entries
        .into_iter()
        .find(|d| d.domain == domain)
        .ok_or(Error("registrar_domain_unobserved"))?;
    let ns = match valuedomain::nameservers(&mut http, &domain) {
        Ok(value) => json!({"state":"supported","data":value}),
        Err(e) => json!({"state":"unobserved","reason":e.code}),
    };
    let renewal = match http.get(&format!("/domains/{domain}/autorenew")) {
        Ok(v) if v["results"]["domainname"] == domain => {
            match valuedomain::effective_auto_renew(&v["results"]) {
                Ok(value) => json!({"state":"supported","enabled":value}),
                Err(e) => json!({"state":"unobserved","reason":e.code}),
            }
        }
        _ => json!({"state":"unobserved","reason":"renewal_unavailable_or_wrong_scope"}),
    };
    Ok(
        json!({"schema":"zix-domain-registrar-observation/v1","domain":domain,"observed_at":now,
        "registration":selected,"nameservers":ns,"auto_renew":renewal,"writes_performed":false}),
    )
}
