//! Local reconciliation of a narrowly observed ValueDomain MX normalization.
use super::*;
use zixcel_domain::valuedomain::StoredDns;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    profile: Profile,
    profile_sha256: String,
    original_plan_file: String,
    original_sha256: String,
    observation: StoredDns,
    created_at: u64,
    expires_at: u64,
}

fn original(
    path: &str,
    profile: &Profile,
    profile_hash: &str,
) -> Result<(String, valuedomain_edit::Plan), Error> {
    let envelope: LocalPlan = read(path)?;
    if envelope.operation != "dns.records.apply" || envelope.binding.package != "zixcel-domain-cli"
    {
        return Err(Error("unsupported_resolution_original"));
    }
    let hash = envelope.digest();
    let payload: Payload = decode(envelope.plan)?;
    if payload.profile != *profile || payload.profile_sha256 != profile_hash {
        return Err(Error("resolution_scope_mismatch"));
    }
    let p: valuedomain_edit::Plan = decode(payload.change)?;
    let Target::Valuedomain { namespace } = &profile.target else {
        return Err(Error("unsupported_resolution_target"));
    };
    if p.before.domain != profile.domain || &p.namespace != namespace {
        return Err(Error("resolution_scope_mismatch"));
    }
    valuedomain_edit::validate_plan(&p, p.created_at)
        .map_err(|_| Error("invalid_original_plan"))?;
    Ok((hash, p))
}

fn observed(p: &valuedomain_edit::Plan, current: &StoredDns) -> Result<(), Error> {
    let mut expected = p.after.clone();
    let mut text = String::new();
    let mut count = 0;
    for chunk in expected.records.split_inclusive('\n') {
        let line = chunk.trim_end_matches('\n');
        let words: Vec<_> = line.split_whitespace().collect();
        if words.len() == 3
            && words[0] == "mx"
            && words[2] == "0"
            && p.change.add.iter().any(|s| s == line)
        {
            text.push_str(
                line.strip_suffix('0')
                    .ok_or(Error("unsupported_normalization"))?,
            );
            if chunk.ends_with('\n') {
                text.push('\n');
            }
            count += 1;
        } else {
            text.push_str(chunk);
        }
    }
    expected.records = text;
    if count == 0 || &expected != current {
        return Err(Error("unrelated_dns_drift"));
    }
    Ok(())
}

pub(super) fn execute(
    r: &Request,
    profile: Profile,
    profile_hash: String,
    deadline: Instant,
) -> Result<Value, Failure> {
    let arg = |k| {
        r.arguments
            .get(k)
            .map(String::as_str)
            .ok_or(Error("missing_argument"))
    };
    let Target::Valuedomain { namespace } = &profile.target else {
        return Err(Error("unsupported_resolution_target").into());
    };
    let mut t = http(Provider::ValueDomain, deadline)?;
    let journal = Journal::open(Path::new(&profile.journal_directory))?;
    if r.operation == "dns.records.resolve.plan" {
        let path = arg("original-plan-file")?;
        let (hash, p) = original(path, &profile, &profile_hash)?;
        journal.pending(&hash, &profile.domain)?;
        let observation =
            valuedomain_edit::read(&mut t, &profile.domain, namespace).map_err(fail)?;
        observed(&p, &observation)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error("clock_unavailable"))?
            .as_secs();
        let plan = LocalPlan::new(
            "dns.records.resolve.apply".into(),
            binding()?,
            encoded(Resolution {
                profile,
                profile_sha256: profile_hash,
                original_plan_file: path.into(),
                original_sha256: hash,
                observation,
                created_at: now,
                expires_at: now + 300,
            })?,
        );
        return Ok(json!({"sha256":plan.digest(),"plan":plan,"writes_performed":false}));
    }
    let envelope: LocalPlan = read(arg("plan-file")?)?;
    if !envelope.matches(
        "dns.records.resolve.apply",
        &binding()?,
        arg("approval-sha256")?,
    ) {
        return Err(Error("plan_binding_mismatch").into());
    }
    let resolution: Resolution = decode(envelope.plan)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error("clock_unavailable"))?
        .as_secs();
    if resolution.profile != profile
        || resolution.profile_sha256 != profile_hash
        || arg("journal-directory")? != profile.journal_directory
    {
        return Err(Error("resolution_scope_mismatch").into());
    }
    if resolution.created_at > now
        || resolution.expires_at != resolution.created_at.saturating_add(300)
        || now >= resolution.expires_at
    {
        return Err(Error("expired_resolution_plan").into());
    }
    let (hash, p) = original(&resolution.original_plan_file, &profile, &profile_hash)?;
    if hash != resolution.original_sha256 {
        return Err(Error("original_plan_changed").into());
    }
    journal.pending(&hash, &profile.domain)?;
    let current = valuedomain_edit::read(&mut t, &profile.domain, namespace).map_err(fail)?;
    observed(&p, &current)?;
    if current != resolution.observation {
        return Err(Error("resolution_snapshot_drift").into());
    }
    let receipt = json!({"schema":"zix-domain-dns-resolution/v1","original_plan_sha256":hash,
        "approved_resolution_sha256":arg("approval-sha256")?,"original_outcome":"unknown",
        "original_replay_allowed":false,"remote_write_attempted":false,"observed_mx_priority_missing":true,
        "observation":current,"state":"recorded"});
    let final_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error("clock_unavailable"))?
        .as_secs();
    if final_now >= resolution.expires_at {
        return Err(Error("expired_resolution_plan").into());
    }
    journal.resolve(&hash, &profile.domain, &receipt)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_requested_zero_priority_mx_normalization_is_accepted() {
        let before = StoredDns {
            domain: "example.test".into(),
            ns_type: "valuedomain11".into(),
            records: "txt @ \"retain\"\n".into(),
            ttl: 3600,
            authority_verified: false,
        };
        let mut after = before.clone();
        after.records.push_str("mx mail.example.test. 0\n");
        let p = valuedomain_edit::Plan {
            namespace: Namespace::Registered,
            before,
            after: after.clone(),
            change: Change {
                add: vec!["mx mail.example.test. 0".into()],
                remove: vec![],
            },
            created_at: 100,
            expires_at: 400,
            nonce: "test".into(),
        };
        let mut current = after.clone();
        current.records = current.records.replace(" 0\n", " \n");
        assert!(observed(&p, &current).is_ok());
        assert!(observed(&p, &after).is_err());
        current.ttl = 60;
        assert!(observed(&p, &current).is_err());
        current.ttl = 3600;
        current.records.push_str("a www 192.0.2.1\n");
        assert!(observed(&p, &current).is_err());
    }
    #[test]
    fn historical_original_is_private_scoped_and_internally_consistent() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("domain-original-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("original.json");
        let profile = Profile {
            domain: "example.test".into(),
            target: Target::Valuedomain {
                namespace: Namespace::Registered,
            },
            journal_directory: root.to_str().unwrap().into(),
        };
        let before = StoredDns {
            domain: "example.test".into(),
            records: "txt @ \"retain\"\n".into(),
            ns_type: "valuedomain11".into(),
            ttl: 3600,
            authority_verified: false,
        };
        let mut after = before.clone();
        after.records.push_str("mx mail.example.test. 0\n");
        let p = valuedomain_edit::Plan {
            namespace: Namespace::Registered,
            before,
            after,
            change: Change {
                add: vec!["mx mail.example.test. 0".into()],
                remove: vec![],
            },
            created_at: 100,
            expires_at: 400,
            nonce: "history".into(),
        };
        let binding =
            Binding::for_catalog("zixcel-domain-cli", "0.3.1", &json!({}), &"a".repeat(64));
        let mut envelope = LocalPlan::new(
            "dns.records.apply".into(),
            binding,
            encoded(Payload {
                profile: profile.clone(),
                profile_sha256: "b".repeat(64),
                change: encoded(p).unwrap(),
            })
            .unwrap(),
        );
        let write = |v: &LocalPlan| {
            std::fs::write(&path, serde_json::to_vec(v).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write(&envelope);
        assert_eq!(
            original(path.to_str().unwrap(), &profile, &"b".repeat(64))
                .unwrap()
                .0,
            envelope.digest()
        );
        assert!(original(path.to_str().unwrap(), &profile, &"c".repeat(64)).is_err());
        envelope.plan["change"]["after"]["ttl"] = json!(60);
        write(&envelope);
        assert!(original(path.to_str().unwrap(), &profile, &"b".repeat(64)).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(original(path.to_str().unwrap(), &profile, &"b".repeat(64)).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
