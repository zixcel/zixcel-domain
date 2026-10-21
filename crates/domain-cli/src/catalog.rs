use zix_cli::manifest::CommandEnvironment;
use zix_native_provider::{Argument, Command, Manifest};
pub fn manifest() -> Manifest {
    let mut m = crate::registrar::base_manifest();
    m.timeout_ms = 40000;
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
    m
}
