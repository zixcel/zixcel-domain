use zix_cli::manifest::CommandEnvironment;
use zix_native_provider::{Argument, Command, Manifest};
pub fn manifest() -> Manifest {
    let mut m = crate::registrar::base_manifest();
    m.timeout_ms = 40000;
    m.schema = "zix-extension/v2".into();
    m.credential_environment
        .push("ZIX_CLOUDFLARE_API_TOKEN".into());
    for (id, words, credential) in [
        ("dns.audit", vec!["dns", "audit"], false),
        ("registrar.inspect", vec!["registrar", "inspect"], true),
        ("dns.reconcile", vec!["reconcile"], false),
    ] {
        let mut arguments = vec![Argument {
            name: if id == "dns.reconcile" {
                "report"
            } else {
                "domain"
            }
            .into(),
            required: true,
            maximum: if id == "dns.reconcile" { 1024 } else { 253 },
        }];
        if id == "dns.audit" {
            arguments.push(Argument {
                name: "authority".into(),
                required: false,
                maximum: 5,
            });
        }
        m.commands.push(Command {
            id: id.into(),
            words: words.into_iter().map(str::to_owned).collect(),
            effect: "read".into(),
            description: "Bounded Domain evidence; unavailable is not safe.".into(),
            required_permissions: if credential {
                vec!["ValueDomain registrar read".into()]
            } else {
                vec![]
            },
            arguments,
            environment: Some(CommandEnvironment {
                credential_environment: if credential {
                    vec!["ZIX_VALUEDOMAIN_ACCESS_TOKEN".into()]
                } else {
                    vec![]
                },
                runtime_environment: vec![],
            }),
        });
    }
    for (id, words, extras, credentials, effect) in [
        (
            "dns.inspect",
            vec!["dns", "inspect"],
            vec!["domain", "type"],
            false,
            "read",
        ),
        (
            "dns.delegation",
            vec!["dns", "delegation"],
            vec!["domain"],
            false,
            "read",
        ),
        (
            "dns.export",
            vec!["dns", "export"],
            vec!["profile"],
            true,
            "read",
        ),
        (
            "dns.records.plan",
            vec!["dns", "records", "plan"],
            vec!["profile", "change-file"],
            true,
            "read",
        ),
        (
            "dns.records.resolve.plan",
            vec!["dns", "records", "resolve", "plan"],
            vec!["profile", "original-plan-file"],
            true,
            "read",
        ),
        (
            "dns.records.resolve.apply",
            vec!["dns", "records", "resolve", "apply"],
            vec![
                "profile",
                "plan-file",
                "approval-sha256",
                "journal-directory",
            ],
            true,
            "operator-write",
        ),
        (
            "dns.records.apply",
            vec!["dns", "records", "apply"],
            vec![
                "profile",
                "plan-file",
                "approval-sha256",
                "journal-directory",
            ],
            true,
            "operator-write",
        ),
        (
            "nameservers.inspect",
            vec!["nameservers", "inspect"],
            vec!["profile"],
            true,
            "read",
        ),
        (
            "nameservers.plan",
            vec!["nameservers", "plan"],
            vec!["profile", "phase"],
            true,
            "read",
        ),
        (
            "nameservers.apply",
            vec!["nameservers", "apply"],
            vec![
                "profile",
                "plan-file",
                "approval-sha256",
                "journal-directory",
            ],
            true,
            "operator-write",
        ),
    ] {
        m.commands.push(Command {
            id:id.into(), words:words.into_iter().map(str::to_owned).collect(),effect:effect.into(),
            description:"Profile-scoped DNS operation; writes require an exact reviewed plan and durable journal.".into(),
            required_permissions:if credentials {vec!["Selected ValueDomain DNS or Cloudflare account permissions; independently verified".into()]}else{vec![]},
            arguments:extras.into_iter().map(|name|Argument{name:name.into(),required:true,maximum:if name=="approval-sha256"{64}else{2048}}).collect(),
            environment:Some(CommandEnvironment{credential_environment:if credentials{vec!["ZIX_VALUEDOMAIN_ACCESS_TOKEN".into(),"ZIX_CLOUDFLARE_API_TOKEN".into()]}else{vec![]},runtime_environment:vec![]}),
        });
    }
    m.commands[0].environment = Some(CommandEnvironment {
        credential_environment: vec!["ZIX_VALUEDOMAIN_ACCESS_TOKEN".into()],
        runtime_environment: vec![],
    });
    m.protocol = "zix-provider/v2".into();
    zix_native_provider::guidance::decorate(&mut m, include_bytes!("../api/guidance.json"))
        .expect("reviewed domain guidance");
    m
}
