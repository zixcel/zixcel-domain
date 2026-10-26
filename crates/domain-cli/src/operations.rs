use crate::journal::{self, Journal};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use zix_native_provider::{Error, Failure, Request};
use zix_operation_contracts::{Binding, LocalPlan};
use zixcel_domain::{
    domain_release::{Plan as MigrationPlan, Session},
    record_editor::{self, Edit, RecordPlan, Scope},
    transport::{HttpTransport, Provider},
    valuedomain_edit::{self, Change, Namespace},
};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Valuedomain {
        namespace: Namespace,
    },
    Cloudflare {
        account: String,
        zone: String,
    },
    Migration {
        account: String,
        allow_empty_registered_unserved: bool,
        retire_unused_mail: bool,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub domain: String,
    pub target: Target,
    pub journal_directory: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    profile: Profile,
    profile_sha256: String,
    change: Value,
}
pub fn read<T: DeserializeOwned>(path: &str) -> Result<T, Error> {
    let path = Path::new(path);
    journal::private(path, false)?;
    let bytes = zix_cli::files::read(path, 900_000, false)?;
    serde_json::from_slice(&bytes).map_err(|_| Error("invalid_input_json"))
}
pub fn binding() -> Result<Binding, Error> {
    let bytes = zix_cli::files::bounded(
        std::fs::File::open("/proc/self/exe").map_err(|_| Error("executable_unavailable"))?,
        32 * 1024 * 1024,
    )?;
    Ok(Binding::for_catalog(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        &serde_json::to_value(crate::manifest()).map_err(|_| Error("invalid_manifest"))?,
        &zix_cli::files::digest(&bytes),
    ))
}
fn fail(e: zixcel_domain::Error) -> Failure {
    Failure {
        code: e.code,
        http_status: e.http_status,
    }
}
fn encoded(v: impl Serialize) -> Result<Value, Error> {
    serde_json::to_value(v).map_err(|_| Error("encoding_failed"))
}
fn decode<T: DeserializeOwned>(v: Value) -> Result<T, Error> {
    serde_json::from_value(v).map_err(|_| Error("invalid_change_or_plan"))
}
fn http(provider: Provider, deadline: Instant) -> Result<HttpTransport, Failure> {
    let mut t = match provider {
        Provider::PublicDns => HttpTransport::public_dns(),
        Provider::ValueDomain => HttpTransport::from_env(provider, "ZIX_VALUEDOMAIN_ACCESS_TOKEN"),
        Provider::Cloudflare => HttpTransport::from_env(provider, "ZIX_CLOUDFLARE_API_TOKEN"),
    }
    .map_err(fail)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error("time_budget"))?;
    t.limit_time(remaining.min(Duration::from_secs(40)))
        .map_err(fail)?;
    Ok(t)
}
fn scoped(profile: &Profile) -> Result<(), Error> {
    if zixcel_domain::domain_name(&profile.domain).map_err(|_| Error("invalid_domain"))?
        != profile.domain
    {
        return Err(Error("invalid_domain"));
    }
    let id = |s: &str| {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    match &profile.target {
        Target::Cloudflare { account, zone } if !id(account) || !id(zone) => {
            return Err(Error("invalid_scope"));
        }
        Target::Migration { account, .. } if !id(account) => return Err(Error("invalid_scope")),
        _ => {}
    }
    Journal::open(Path::new(&profile.journal_directory))?;
    Ok(())
}
pub fn execute(r: &Request) -> Result<Value, Failure> {
    let arg = |k| {
        r.arguments
            .get(k)
            .map(String::as_str)
            .ok_or(Error("missing_argument"))
    };
    let deadline = Instant::now() + Duration::from_millis(r.limits.timeout_ms.saturating_sub(100));
    if r.operation == "dns.inspect" {
        let kind = arg("type")?;
        if ![
            "A", "AAAA", "CNAME", "NS", "SOA", "DS", "DNSKEY", "MX", "TXT", "CAA",
        ]
        .contains(&kind)
        {
            return Err(Error("unsupported_dns_query").into());
        }
        let domain = arg("domain")?;
        zixcel_domain::dns_name::record_name(domain).map_err(fail)?;
        return encoded(
            zixcel_domain::public_dns::query(
                &mut http(Provider::PublicDns, deadline)?,
                domain,
                kind,
            )
            .map_err(fail)?,
        )
        .map_err(Into::into);
    }
    if r.operation == "dns.delegation" {
        let domain = zixcel_domain::domain_name(arg("domain")?).map_err(fail)?;
        use zixcel_domain::transport::ReadTransport;
        return Ok(
            json!({"domain":domain,"nameservers":http(Provider::PublicDns,deadline)?.delegation(&domain).map_err(fail)?,"dnssec_validated":false}),
        );
    }
    let path = arg("profile")?;
    let profile: Profile = read(path)?;
    scoped(&profile)?;
    // Raw profile digest also detects any file edit between plan and apply.
    let profile_hash =
        zix_cli::files::digest(&zix_cli::files::read(Path::new(path), 32 * 1024, false)?);
    let migration = r.operation.starts_with("nameservers.");
    if migration != matches!(profile.target, Target::Migration { .. }) {
        return Err(Error("profile_operation_mismatch").into());
    }
    let apply = r.operation.ends_with(".apply");
    let approved = if apply {
        let p: LocalPlan = read(arg("plan-file")?)?;
        if !p.matches(&r.operation, &binding()?, arg("approval-sha256")?) {
            return Err(Error("plan_binding_mismatch").into());
        }
        let payload: Payload = decode(p.plan)?;
        if payload.profile != profile || payload.profile_sha256 != profile_hash {
            return Err(Error("plan_scope_mismatch").into());
        }
        Some(payload.change)
    } else {
        None
    };
    let change = if r.operation == "dns.records.plan" {
        Some(read::<Value>(arg("change-file")?)?)
    } else {
        None
    };
    // Validate all change/plan types and target scopes before credentials or journal admission.
    match &profile.target {
        Target::Valuedomain { namespace } => {
            if let Some(v) = &change {
                let _: Change = decode(v.clone())?;
            }
            if let Some(v) = &approved {
                let p: valuedomain_edit::Plan = decode(v.clone())?;
                if p.namespace != *namespace || p.before.domain != profile.domain {
                    return Err(Error("plan_scope_mismatch").into());
                }
            }
        }
        Target::Cloudflare { account, zone } => {
            if let Some(v) = &change {
                let _: Edit = decode(v.clone())?;
            }
            if let Some(v) = &approved {
                let p: RecordPlan = decode(v.clone())?;
                if p.scope
                    != (Scope {
                        domain: profile.domain.clone(),
                        account: account.clone(),
                        zone: zone.clone(),
                    })
                {
                    return Err(Error("plan_scope_mismatch").into());
                }
            }
        }
        Target::Migration {
            account,
            allow_empty_registered_unserved,
            retire_unused_mail,
        } => {
            if let Some(v) = &approved {
                let p: MigrationPlan = decode(v.clone())?;
                if p.domain != profile.domain
                    || &p.account != account
                    || p.retire_unused_mail != *retire_unused_mail
                    || (p.source.source_mode
                        == zixcel_domain::domain_release::SourceMode::EmptyRegisteredUnserved
                        && !allow_empty_registered_unserved)
                {
                    return Err(Error("plan_scope_mismatch").into());
                }
            }
            if r.operation == "nameservers.plan"
                && !matches!(arg("phase")?, "prepare_zone" | "change_nameservers")
            {
                return Err(Error("invalid_phase").into());
            }
        }
    }
    let admission = if apply {
        if arg("journal-directory")? != profile.journal_directory {
            return Err(Error("journal_scope_mismatch").into());
        }
        Some(
            Journal::open(Path::new(&profile.journal_directory))?
                .admit(arg("approval-sha256")?, &profile.domain)?,
        )
    } else {
        None
    };
    let result: Result<Value, Failure> = (|| match &profile.target {
        Target::Valuedomain { namespace } => {
            let mut t = http(Provider::ValueDomain, deadline)?;
            if let Some(v) = approved {
                return valuedomain_edit::apply(&decode(v)?, &mut t).map_err(fail);
            }
            if let Some(v) = change {
                return encoded(
                    valuedomain_edit::plan(&mut t, &profile.domain, namespace.clone(), decode(v)?)
                        .map_err(fail)?,
                )
                .map_err(Into::into);
            }
            encoded(valuedomain_edit::read(&mut t, &profile.domain, namespace).map_err(fail)?)
                .map_err(Into::into)
        }
        Target::Cloudflare { account, zone } => {
            let mut t = http(Provider::Cloudflare, deadline)?;
            if let Some(v) = approved {
                let receipt = record_editor::apply_reviewed(&decode(v)?, &mut t).map_err(fail)?;
                let mut v = encoded(receipt)?;
                v["status"] = v["state"].clone();
                return Ok(v);
            }
            let scope = Scope {
                domain: profile.domain.clone(),
                account: account.clone(),
                zone: zone.clone(),
            };
            if let Some(v) = change {
                return encoded(
                    record_editor::Editor::new(scope)
                        .map_err(fail)?
                        .plan(decode(v)?, &mut t)
                        .map_err(fail)?
                        .plan,
                )
                .map_err(Into::into);
            }
            encoded(record_editor::snapshot(scope, &mut t).map_err(fail)?).map_err(Into::into)
        }
        Target::Migration {
            account,
            allow_empty_registered_unserved,
            retire_unused_mail,
        } => {
            let mut registrar = http(Provider::ValueDomain, deadline)?;
            let mut dns = http(Provider::Cloudflare, deadline)?;
            let mut public = http(Provider::PublicDns, deadline)?;
            if let Some(v) = approved {
                return Session::apply_reviewed(decode(v)?, &mut registrar, &mut dns, &mut public)
                    .map_err(fail);
            }
            let mut s = Session::new(&profile.domain, account).map_err(fail)?;
            if *allow_empty_registered_unserved {
                s = s.allow_empty_registered_unserved();
            }
            if *retire_unused_mail {
                s = s.retire_unused_mail();
            }
            if r.operation == "nameservers.plan" {
                return Ok(s
                    .plan(arg("phase")?, &mut registrar, &mut dns, &mut public)
                    .map_err(fail)?["plan"]
                    .clone());
            }
            s.observe(&mut registrar, &mut dns, &mut public)
                .map_err(fail)
        }
    })();
    if let Some(a) = admission {
        let release = result
            .as_ref()
            .is_ok_and(|v| v["status"] == "provider_verified" || v["status"] == "rejected");
        let status = match &result {
            Ok(v) => v.to_string(),
            Err(e) => json!({"status":"readback_required","error":e.code}).to_string(),
        };
        a.finish(&status, release)?;
        return result;
    }
    let value = result?;
    if r.operation.ends_with(".plan") {
        let operation = if migration {
            "nameservers.apply"
        } else {
            "dns.records.apply"
        };
        let envelope = LocalPlan::new(
            operation.into(),
            binding()?,
            encoded(Payload {
                profile,
                profile_sha256: profile_hash,
                change: value,
            })?,
        );
        let result = json!({"plan":envelope,"sha256":envelope.digest(),"writes_performed":false});
        if serde_json::to_vec(&result)
            .map_err(|_| Error("encoding_failed"))?
            .len()
            > r.limits.maximum_response_bytes.saturating_sub(1024)
        {
            return Err(Error("plan_byte_budget").into());
        }
        Ok(result)
    } else {
        Ok(json!({"data":value,"writes_performed":false}))
    }
}
