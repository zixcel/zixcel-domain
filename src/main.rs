use std::io::{Read, Write};
use zixcel_domain::public_dns;
use zixcel_domain::{
    DomainBinding, Result, cloudflare, dns_import, inspection, mapping,
    transport::{HttpTransport, Provider},
    validate_bindings, valuedomain,
};

fn run(args: &[String]) -> Result<serde_json::Value> {
    if let Some(result) = zixcel_domain::security_cli::run(args) {
        return result.map(|value| serde_json::json!({"schema_version":1,"result":value}));
    }
    let failure = || zixcel_domain::Error::new("invalid_command");
    let value = match args {
        [command] if command == "version" || command == "--version" => serde_json::json!({
            "version":env!("CARGO_PKG_VERSION"),
            "source_sha":option_env!("ZIXCEL_DOMAIN_SOURCE_SHA"),
        }),
        [command] if command == "capabilities" => serde_json::json!({
            "schema_version": 1, "registrar": "valuedomain-v2", "dns": "cloudflare",
            "operations": ["dns-security-audit", "securitytxt-preview", "inventory", "inspect", "mapping-preview", "dns-source-preview", "dns-import-preview", "public-dns", "public-nameservers", "public-delegation", "valuedomain-domains", "valuedomain-settings", "valuedomain-free-dns", "valuedomain-nameservers", "domain-session", "domain-control", "record-session", "cloudflare-zones", "cloudflare-records", "validate-bindings"],
            "writes_supported": true, "live_acceptance": false,
            "write_operations": ["prepare_zone", "change_nameservers", "record_create", "record_update", "record_delete"],
            "record_session": {"command":"record-session", "protocol":1, "record_types":["A","AAAA","CNAME","TXT","MX"], "actions":["plan","apply","status","stop"], "request_bytes":8192, "response_bytes":1048576, "request_limit":100},
            "write_boundary": "scoped_local_session_one_use_plan_hash_approval",
            "token_permissions_verified": false
        }),
        #[cfg(unix)]
        [command, socket, domain, account, flags @ ..] if command == "domain-session" => {
            if flags.len() > 2
                || flags.iter().any(|flag| {
                    !matches!(
                        flag.as_str(),
                        "--allow-empty-registered-unserved" | "--retire-unused-mail"
                    )
                })
                || (flags.len() == 2 && flags[0] == flags[1])
            {
                return Err(zixcel_domain::Error::new("invalid_session_policy"));
            }
            zixcel_domain::domain_session::serve_with_policies(
                socket,
                domain,
                account,
                flags
                    .iter()
                    .any(|f| f == "--allow-empty-registered-unserved"),
                flags.iter().any(|f| f == "--retire-unused-mail"),
            )?
        }
        #[cfg(unix)]
        [command, socket, action, argument] if command == "domain-control" => {
            zixcel_domain::domain_session::control(socket, action, Some(argument))?
        }
        #[cfg(unix)]
        [command, socket, action] if command == "domain-control" => {
            zixcel_domain::domain_session::control(socket, action, None)?
        }
        [command, domain] if command == "valuedomain-nameservers" => {
            let mut transport =
                HttpTransport::from_env(Provider::ValueDomain, "VALUEDOMAIN_ACCESS_TOKEN")?;
            serde_json::to_value(valuedomain::nameservers(&mut transport, domain)?)
                .map_err(|_| failure())?
        }
        [command, domain] if command == "valuedomain-free-dns" => {
            let mut transport =
                HttpTransport::from_env(Provider::ValueDomain, "VALUEDOMAIN_ACCESS_TOKEN")?;
            serde_json::to_value(valuedomain::free_dns(&mut transport, domain)?)
                .map_err(|_| failure())?
        }
        [command, domain, record_type] if command == "public-dns" => {
            let mut transport = HttpTransport::public_dns()?;
            serde_json::to_value(public_dns::query(&mut transport, domain, record_type)?)
                .map_err(|_| failure())?
        }
        [command] if command == "dns-source-preview" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                nameservers: Vec<String>,
                assigned_cloudflare: Option<Vec<String>>,
            }
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(8193)
                .read_to_end(&mut bytes)
                .map_err(|_| failure())?;
            if bytes.len() > 8192 {
                return Err(zixcel_domain::Error::new("input_budget"));
            }
            let input: Input = serde_json::from_slice(&bytes)
                .map_err(|_| zixcel_domain::Error::new("invalid_manifest"))?;
            let source = inspection::configured_dns(
                &input.nameservers,
                input.assigned_cloudflare.as_deref(),
            )?;
            serde_json::json!({"configured_dns":source,"authority_verified":false,"writes_performed":false})
        }
        [command] if command == "dns-import-preview" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                domain: String,
                ttl: u32,
                records: String,
            }
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(256 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| failure())?;
            if bytes.len() > 256 * 1024 {
                return Err(zixcel_domain::Error::new("input_budget"));
            }
            let input: Input = serde_json::from_slice(&bytes)
                .map_err(|_| zixcel_domain::Error::new("invalid_manifest"))?;
            let records = dns_import::parse(&input.domain, input.ttl, &input.records)?;
            serde_json::json!({"kind":"dns_import_preview","records":records,"writes_performed":false})
        }
        [command] if command == "mapping-preview" => {
            let mut input = Vec::new();
            std::io::stdin()
                .take(256 * 1024 + 1)
                .read_to_end(&mut input)
                .map_err(|_| failure())?;
            if input.len() > 256 * 1024 {
                return Err(zixcel_domain::Error::new("input_budget"));
            }
            let input: mapping::MappingInput = serde_json::from_slice(&input)
                .map_err(|_| zixcel_domain::Error::new("invalid_manifest"))?;
            serde_json::to_value(mapping::preview(&input)?).map_err(|_| failure())?
        }
        [command, domain] if command == "public-delegation" => {
            serde_json::json!({"domain":zixcel_domain::domain_name(domain)?,"nameservers":zixcel_domain::delegation::query(domain)?,"observation":"parent_referral","dnssec_validated":false,"writes_performed":false})
        }
        [command, domain] if command == "public-nameservers" => {
            let mut transport = HttpTransport::public_dns()?;
            serde_json::to_value(inspection::public_nameservers(&mut transport, domain)?)
                .map_err(|_| failure())?
        }
        [command, account] if command == "inspect" => {
            let mut registrar =
                HttpTransport::from_env(Provider::ValueDomain, "VALUEDOMAIN_ACCESS_TOKEN")?;
            let mut dns = HttpTransport::from_env(Provider::Cloudflare, "CLOUDFLARE_API_TOKEN")?;
            serde_json::to_value(inspection::inspect(&mut registrar, &mut dns, account)?)
                .map_err(|_| failure())?
        }
        [command, account] if command == "inventory" => {
            let mut registrar =
                HttpTransport::from_env(Provider::ValueDomain, "VALUEDOMAIN_ACCESS_TOKEN")?;
            let mut dns = HttpTransport::from_env(Provider::Cloudflare, "CLOUDFLARE_API_TOKEN")?;
            let domains = valuedomain::domains(&mut registrar)?;
            let zones = cloudflare::zones(&mut dns, account)?;
            serde_json::json!({"registrar_domains": domains, "cloudflare_zones": zones,
                "organization_binding": "explicit_manifest_required", "writes_performed": false})
        }
        [command, flag]
            if command == "valuedomain-domains" && flag == "--exclude-auto-renew-disabled" =>
        {
            let mut transport =
                HttpTransport::from_env(Provider::ValueDomain, "VALUEDOMAIN_ACCESS_TOKEN")?;
            serde_json::to_value(valuedomain::domains_excluding_auto_renew_disabled(
                &mut transport,
            )?)
            .map_err(|_| failure())?
        }
        [command] if command == "valuedomain-domains" => {
            let mut transport =
                HttpTransport::from_env(Provider::ValueDomain, "VALUEDOMAIN_ACCESS_TOKEN")?;
            serde_json::to_value(valuedomain::domains(&mut transport)?).map_err(|_| failure())?
        }
        [command, domain] if command == "valuedomain-settings" => {
            let mut transport =
                HttpTransport::from_env(Provider::ValueDomain, "VALUEDOMAIN_ACCESS_TOKEN")?;
            serde_json::to_value(valuedomain::settings(&mut transport, domain)?)
                .map_err(|_| failure())?
        }
        [command, account] if command == "cloudflare-zones" => {
            let mut transport =
                HttpTransport::from_env(Provider::Cloudflare, "CLOUDFLARE_API_TOKEN")?;
            serde_json::to_value(cloudflare::zones(&mut transport, account)?)
                .map_err(|_| failure())?
        }
        [command, zone] if command == "cloudflare-records" => {
            let mut transport =
                HttpTransport::from_env(Provider::Cloudflare, "CLOUDFLARE_API_TOKEN")?;
            serde_json::to_value(cloudflare::records(&mut transport, zone)?)
                .map_err(|_| failure())?
        }
        [command] if command == "validate-bindings" => {
            let mut input = Vec::new();
            std::io::stdin()
                .take(256 * 1024 + 1)
                .read_to_end(&mut input)
                .map_err(|_| failure())?;
            if input.len() > 256 * 1024 {
                return Err(zixcel_domain::Error::new("input_budget"));
            }
            let bindings: Vec<DomainBinding> = serde_json::from_slice(&input)
                .map_err(|_| zixcel_domain::Error::new("invalid_manifest"))?;
            validate_bindings(&bindings)?;
            serde_json::json!({"valid": true, "bindings": bindings.len()})
        }
        _ => return Err(failure()),
    };
    Ok(serde_json::json!({"schema_version": 1, "result": value}))
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let [command, account, zone, domain] = args.as_slice()
        && command == "record-session"
    {
        let result = (|| -> Result<()> {
            let scope = zixcel_domain::record_editor::Scope {
                account: account.clone(),
                zone: zone.clone(),
                domain: domain.clone(),
            };
            zixcel_domain::record_editor::Editor::new(scope.clone())?;
            zixcel_domain::record_cli::serve_live(
                scope,
                std::io::stdin().lock(),
                std::io::stdout().lock(),
            )
        })();
        if let Err(error) = result {
            let value = serde_json::json!({"schema_version":1,"error":error});
            let _ = writeln!(std::io::stdout().lock(), "{value}");
            std::process::exit(1);
        }
        return;
    }
    let (value, code) = match run(&args) {
        Ok(value) => {
            let code = if value["result"]["complete_for_dns_plan"].as_bool() == Some(false)
                || matches!(
                    value["result"]["status"].as_str(),
                    Some("rejected" | "partial_or_unknown")
                ) {
                2
            } else {
                0
            };
            (value, code)
        }
        Err(error) => (serde_json::json!({"schema_version": 1, "error": error}), 1),
    };
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &value).is_err() || writeln!(stdout).is_err() {
        std::process::exit(1);
    }
    std::process::exit(code);
}
