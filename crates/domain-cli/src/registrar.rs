//! zix protocol adapter over existing ValueDomain inventory, never a second DNS client.
use serde_json::{Value, json};
use zix_native_provider::{Argument, Command, Error, Failure, Manifest, Request, validate_request};
use zixcel_domain::{
    transport::{HttpTransport, Provider, ReadTransport},
    valuedomain,
};
pub(super) fn base_manifest() -> Manifest {
    Manifest {
        schema: "zix-extension/v1".into(),
        package: "zixcel-domain-cli".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        namespace: "domain".into(),
        platform: "linux-x86_64".into(),
        protocol: "zix-provider/v1".into(),
        credential_environment: vec!["ZIX_VALUEDOMAIN_ACCESS_TOKEN".into()],
        runtime_environment: vec![],
        timeout_ms: 35000,
        commands: vec![Command {
            environment: None,
            id: "valuedomain.domains.list".into(),
            words: vec!["list".into()],
            effect: "read".into(),
            description: "List credential-visible ValueDomain v2 domains.".into(),
            required_permissions: vec!["ValueDomain v2 domain and optional renewal reads".into()],
            arguments: vec![Argument {
                name: "exclude-auto-renew-disabled".into(),
                required: false,
                maximum: 5,
            }],
        }],
    }
}
fn exclude(request: &Request) -> Result<bool, Failure> {
    validate_request(&crate::manifest(), request).map_err(Failure::from)?;
    if request.operation != "valuedomain.domains.list" {
        return Err(Error("unknown_operation").into());
    }
    match request
        .arguments
        .get("exclude-auto-renew-disabled")
        .map(String::as_str)
    {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err(Error("invalid_renewal_filter").into()),
    }
}
fn failure(error: zixcel_domain::Error) -> Failure {
    Failure {
        code: error.code,
        http_status: error.http_status,
    }
}
pub fn observe(request: &Request, transport: &mut impl ReadTransport) -> Result<Value, Failure> {
    let exclude = exclude(request)?;
    let domains = if exclude {
        valuedomain::domains_excluding_auto_renew_disabled(transport)
    } else {
        valuedomain::domains(transport)
    }
    .map_err(failure)?;
    Ok(
        json!({"schema":"zix-domain-inventory/v1","provider":"valuedomain-v2","domains":domains,
        "exclude_auto_renew_disabled":exclude,"scope":"credential_visible","permission_state":"not_inferred","writes_performed":false}),
    )
}
pub(super) fn execute(request: &Request) -> Result<Value, Failure> {
    exclude(request)?; // Reject unexpected arguments before reading credentials or starting HTTP.
    let mut transport =
        HttpTransport::from_env(Provider::ValueDomain, "ZIX_VALUEDOMAIN_ACCESS_TOKEN")
            .map_err(failure)?;
    transport
        .limit_time(std::time::Duration::from_millis(
            request.limits.timeout_ms.saturating_sub(20).max(50),
        ))
        .map_err(failure)?;
    observe(request, &mut transport)
}
