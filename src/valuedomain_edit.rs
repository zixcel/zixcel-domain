//! Exact-line edits over VDAPI's whole-zone PUT. Unselected bytes, service and TTL stay fixed.
use crate::{
    Result, approval, dns_import, domain_name, error,
    transport::{ReadTransport, WriteTransport},
    valuedomain::{self, StoredDns},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Namespace {
    Registered,
    Free,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub add: Vec<String>,
    pub remove: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub namespace: Namespace,
    pub before: StoredDns,
    pub after: StoredDns,
    pub change: Change,
    pub created_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}
pub fn read(t: &mut impl ReadTransport, domain: &str, namespace: &Namespace) -> Result<StoredDns> {
    match namespace {
        Namespace::Registered => {
            let domain = domain_name(domain)?;
            if !valuedomain::domains(t)?.iter().any(|d| d.domain == domain) {
                return Err(error("domain_not_in_inventory"));
            }
            valuedomain::stored_dns(t, &domain)
        }
        Namespace::Free => valuedomain::free_dns(t, domain),
    }
}
fn edited(before: &StoredDns, c: &Change) -> Result<StoredDns> {
    if !matches!(before.ns_type.as_str(), "valuedomain1" | "valuedomain11")
        || before.records.len() > 100_000
        || c.add.len() + c.remove.len() == 0
        || c.add.len() + c.remove.len() > 50
    {
        return Err(error("invalid_dns_change"));
    }
    let ttl = u32::try_from(before.ttl).map_err(|_| error("invalid_dns"))?;
    let mut selected = std::collections::BTreeSet::new();
    for line in c.add.iter().chain(&c.remove) {
        if line.is_empty()
            || line.len() > 8192
            || line.contains(['\n', '\r', '\0'])
            || !selected.insert(line)
        {
            return Err(error("invalid_or_duplicate_line"));
        }
        // A provider may store a zero-priority MX with its priority missing.
        // Permit its exact removal only, never adding malformed source text.
        let words: Vec<_> = line.split_whitespace().collect();
        if c.remove.contains(line)
            && words.len() == 2
            && words[0] == "mx"
            && crate::domain_name(words[1].trim_end_matches('.')).is_ok()
        {
            continue;
        }
        let parsed = dns_import::parse(&before.domain, ttl, line)?;
        if parsed.len() != 1
            || !matches!(parsed[0].record_type, "A" | "AAAA" | "CNAME" | "TXT" | "MX")
        {
            return Err(error("unsupported_record_type"));
        }
    }
    for line in &c.remove {
        if before
            .records
            .split_inclusive('\n')
            .filter(|s| s.trim_end_matches(['\r', '\n']) == line)
            .count()
            != 1
        {
            return Err(error("remove_line_missing_or_ambiguous"));
        }
    }
    let mut text = String::new();
    for chunk in before.records.split_inclusive('\n') {
        if !c
            .remove
            .iter()
            .any(|s| s == chunk.trim_end_matches(['\r', '\n']))
        {
            text.push_str(chunk);
        }
    }
    // Validate final recognized RRsets. Unknown source directives remain byte-for-byte;
    // additions are refused when their interaction cannot be established.
    let mut known = Vec::new();
    for line in text
        .lines()
        .filter(|s| !s.trim().is_empty() && !s.trim_start().starts_with('#'))
    {
        match dns_import::parse(&before.domain, ttl, line) {
            Ok(records) => known.extend(records),
            Err(_) if c.add.is_empty() => {}
            Err(_) => return Err(error("unknown_source_syntax_blocks_addition")),
        }
    }
    for line in &c.add {
        let record = dns_import::parse(&before.domain, ttl, line)?.remove(0);
        for other in &known {
            if other.name == record.name {
                if other.record_type == "CNAME" || record.record_type == "CNAME" {
                    return Err(error("record_name_conflict"));
                }
                if other.record_type == record.record_type
                    && other.content == record.content
                    && other.priority == record.priority
                {
                    return Err(error("duplicate_record"));
                }
                if record.record_type == "TXT"
                    && record
                        .content
                        .as_deref()
                        .is_some_and(|s| s.trim_matches('"').to_lowercase().starts_with("v=spf1"))
                    && other
                        .content
                        .as_deref()
                        .is_some_and(|s| s.trim_matches('"').to_lowercase().starts_with("v=spf1"))
                {
                    return Err(error("duplicate_spf"));
                }
            }
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(line);
        text.push('\n');
        known.push(record);
    }
    if text.len() > 100_000 {
        return Err(error("input_budget"));
    }
    let mut after = before.clone();
    after.records = text;
    Ok(after)
}
pub fn plan(
    t: &mut impl ReadTransport,
    domain: &str,
    namespace: Namespace,
    change: Change,
) -> Result<Plan> {
    let before = read(t, domain, &namespace)?;
    let after = edited(&before, &change)?;
    safe_priority(&before, &change)?;
    let now = approval::now()?;
    Ok(Plan {
        namespace,
        before,
        after,
        change,
        created_at: now,
        expires_at: now + 300,
        nonce: approval::nonce()?,
    })
}
/// Caller must bind executable/profile and durably consume the approval first.
pub fn apply(p: &Plan, t: &mut impl WriteTransport) -> Result<Value> {
    safe_priority(&p.before, &p.change)?;
    let check_time = || -> Result<()> {
        let now = approval::now()?;
        if p.created_at > now
            || p.expires_at != p.created_at.saturating_add(300)
            || now >= p.expires_at
        {
            return Err(error("expired_or_modified_plan"));
        }
        Ok(())
    };
    check_time()?;
    if edited(&p.before, &p.change)? != p.after {
        return Err(error("invalid_plan"));
    }
    if read(t, &p.before.domain, &p.namespace)? != p.before {
        return Err(error("snapshot_drift"));
    }
    check_time()?;
    let path = match p.namespace {
        Namespace::Registered => format!("/domains/{}/dns", p.before.domain),
        Namespace::Free => format!("/freedns/{}", p.before.domain),
    };
    let mut body = json!({"records":p.after.records,"ttl":p.before.ttl});
    if p.namespace == Namespace::Registered {
        body["ns_type"] = json!(p.before.ns_type);
    }
    // Every error after entering PUT is an uncertain effect; never replay.
    let result = t.put(&path, &body).and_then(|_| {
        if read(t, &p.before.domain, &p.namespace)? != p.after {
            return Err(error("dns_readback_mismatch"));
        }
        Ok(())
    });
    Ok(match result {
        Ok(()) => {
            json!({"status":"provider_verified","writes_attempted":1,"public_propagation":"pending_separate_verification"})
        }
        Err(e) => {
            json!({"status":"outcome_unknown","writes_attempted":1,"error":e,"blind_replay_allowed":false})
        }
    })
}

fn safe_priority(before: &StoredDns, change: &Change) -> Result<()> {
    for line in &change.add {
        let ttl = u32::try_from(before.ttl).map_err(|_| error("invalid_dns"))?;
        for record in dns_import::parse(&before.domain, ttl, line)? {
            if record.record_type == "MX" && record.priority == Some(0) {
                return Err(error("zero_mx_priority_not_roundtrip_safe"));
            }
        }
    }
    Ok(())
}

/// Validate a saved plan without provider access; historical inspection uses its creation time.
pub fn validate_plan(p: &Plan, now: u64) -> Result<()> {
    if p.created_at > now || p.expires_at != p.created_at.saturating_add(300) || now >= p.expires_at
    {
        return Err(error("expired_or_modified_plan"));
    }
    if edited(&p.before, &p.change)? != p.after {
        return Err(error("invalid_plan"));
    }
    Ok(())
}
