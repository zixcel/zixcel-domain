//! Scoped, one-use DNS migration plans. Credentials remain in trusted transports.
use crate::{
    Result, cloudflare, dns_import, domain_name, error, public_dns,
    transport::{ReadTransport, WriteTransport},
    valid_id, valuedomain,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub source_mode: SourceMode,
    pub domain: String,
    pub registrar_nameservers: Vec<String>,
    pub public_nameservers: Vec<String>,
    pub parent_delegation_nameservers: Vec<String>,
    pub public_soa: String,
    pub dns_service: String,
    pub records: String,
    pub ttl: u32,
    pub parent_ds_present: bool,
    pub observed_apex_mail: Vec<Value>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMode {
    RegisteredAndPublicObserved,
    EmptyRegisteredUnserved,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneState {
    pub id: String,
    pub nameservers: Vec<String>,
    pub status: String,
    pub records: Vec<Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub implementation_version: String,
    pub implementation_source_sha: Option<String>,
    pub phase: String,
    pub domain: String,
    pub account: String,
    pub source: Source,
    pub zone: Option<ZoneState>,
    pub records_to_preserve: Vec<Value>,
    pub records_to_retire: Vec<Value>,
    pub records_to_add: Vec<Value>,
    pub retire_unused_mail: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}
pub fn digest(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| error("invalid_plan"))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| error("invalid_clock"))
}
fn sorted(mut names: Vec<String>) -> Vec<String> {
    names.sort();
    names.dedup();
    names
}

pub fn source(
    registrar: &mut impl ReadTransport,
    public: &mut impl ReadTransport,
    input: &str,
) -> Result<Source> {
    let domain = domain_name(input)?;
    if !valuedomain::domains(registrar)?
        .iter()
        .any(|x| x.domain == domain)
    {
        return Err(error("domain_not_in_inventory"));
    }
    let registrar_nameservers = sorted(valuedomain::nameservers(registrar, &domain)?);
    let public_nameservers = sorted(
        public_dns::query(public, &domain, "NS")?
            .answers
            .into_iter()
            .map(|a| domain_name(&a.data))
            .collect::<Result<Vec<_>>>()?,
    );
    if public_nameservers.is_empty() {
        return Err(error("authoritative_source_unknown"));
    }
    let parent_delegation_nameservers = sorted(public.delegation(&domain)?);
    if parent_delegation_nameservers.is_empty() {
        return Err(error("delegation_missing"));
    }
    let is_service = |numbers: &[u8]| {
        parent_delegation_nameservers.iter().all(|n| {
            numbers
                .iter()
                .any(|v| *n == format!("ns{v}.value-domain.com"))
        })
    };
    let registered = valuedomain::stored_dns(registrar, &domain)?;
    let dns = if is_service(&[1, 2, 3, 4, 5]) {
        if registered.ns_type == "valuedomain1" {
            registered
        } else {
            valuedomain::free_dns(registrar, &domain)?
        }
    } else if is_service(&[11, 12, 13]) {
        if registered.ns_type != "valuedomain11" {
            return Err(error("authoritative_source_mismatch"));
        }
        registered
    } else {
        return Err(error("authoritative_source_unknown"));
    };
    let ttl = u32::try_from(dns.ttl).map_err(|_| error("invalid_dns"))?;
    if dns.records.len() > 256 * 1024 {
        return Err(error("input_budget"));
    }
    let soa = public_dns::query(public, &domain, "SOA")?;
    if soa.answers.len() != 1 {
        return Err(error("authoritative_source_mismatch"));
    }
    let ds = public_dns::query(public, &domain, "DS")?;
    let mut observed_apex_mail = Vec::new();
    for kind in ["MX", "TXT"] {
        for answer in public_dns::query(public, &domain, kind)?.answers {
            let mut record = json!({"type":kind,"name":domain,"content":answer.data});
            if kind == "MX" {
                let words: Vec<_> = answer.data.split_whitespace().collect();
                if words.len() != 2 {
                    return Err(error("invalid_public_mx"));
                }
                record["priority"] = json!(
                    words[0]
                        .parse::<u16>()
                        .map_err(|_| error("invalid_public_mx"))?
                );
                record["content"] = json!(words[1]);
            }
            observed_apex_mail.push(record);
        }
    }
    observed_apex_mail.sort_by_key(Value::to_string);
    Ok(Source {
        source_mode: SourceMode::RegisteredAndPublicObserved,
        domain,
        registrar_nameservers,
        public_nameservers,
        parent_delegation_nameservers,
        public_soa: soa.answers[0].data.clone(),
        dns_service: dns.ns_type,
        records: dns.records,
        ttl,
        parent_ds_present: !ds.answers.is_empty(),
        observed_apex_mail,
    })
}
pub fn zone_state(
    dns: &mut impl ReadTransport,
    account: &str,
    domain: &str,
) -> Result<Option<ZoneState>> {
    let matches: Vec<_> = cloudflare::zones(dns, account)?
        .into_iter()
        .filter(|z| z.domain == domain)
        .collect();
    if matches.len() > 1 {
        return Err(error("ambiguous_zone"));
    }
    matches
        .into_iter()
        .next()
        .map(|zone| {
            if !matches!(zone.status.as_str(), "pending" | "active") {
                return Err(error("invalid_zone_state"));
            }
            if zone.nameservers.len() < 2
                || !zone
                    .nameservers
                    .iter()
                    .all(|n| n.ends_with(".ns.cloudflare.com"))
            {
                return Err(error("invalid_zone_nameservers"));
            }
            Ok(ZoneState {
                records: cloudflare::records(dns, &zone.id)?,
                id: zone.id,
                nameservers: sorted(zone.nameservers),
                status: zone.status,
            })
        })
        .transpose()
}
fn normalized(record: &Value) -> Value {
    let mut value = serde_json::Map::new();
    for key in [
        "type", "name", "content", "ttl", "proxied", "priority", "data",
    ] {
        if let Some(v) = record.get(key) {
            value.insert(key.to_owned(), v.clone());
        }
    }
    if let Some(s) = value
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        let text = if record["type"] == "TXT" {
            s.strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(&s)
                .to_owned()
        } else if matches!(record["type"].as_str(), Some("MX" | "CNAME")) {
            s.trim_end_matches('.').to_lowercase()
        } else {
            s
        };
        value.insert("content".into(), Value::String(text));
    }
    Value::Object(value)
}
pub fn contains_record(existing: &[Value], desired: &Value) -> bool {
    existing
        .iter()
        .any(|r| normalized(r) == normalized(desired))
}
fn desired(source: &Source, retire_mail: bool) -> Result<(Vec<Value>, Vec<Value>, Vec<Value>)> {
    let records = serde_json::to_value(dns_import::parse(
        &source.domain,
        source.ttl,
        &source.records,
    )?)
    .map_err(|_| error("invalid_dns"))?;
    let records = records.as_array().ok_or_else(|| error("invalid_dns"))?;
    if records.len() > 50 {
        return Err(error("migration_record_budget"));
    }
    if !retire_mail {
        if records.iter().any(|r| {
            r["type"] == "MX"
                && r["content"]
                    .as_str()
                    .is_some_and(|s| s.trim_end_matches('.') == source.domain)
        }) {
            return Err(error("mail_depends_on_web_apex"));
        }
        for record in records {
            if record["type"] == "TXT" {
                let text = record["content"]
                    .as_str()
                    .unwrap_or("")
                    .trim_matches('"')
                    .to_lowercase();
                if text.starts_with("v=spf1")
                    && text.split_whitespace().any(|t| {
                        let mechanism = t.trim_start_matches(['+', '-', '~', '?']);
                        mechanism == "a"
                            || mechanism.starts_with("a/")
                            || mechanism == format!("a:{}", source.domain)
                            || mechanism.starts_with(&format!("a:{}/", source.domain))
                    })
                {
                    return Err(error("mail_depends_on_web_apex"));
                }
            }
        }
    }
    for observed in &source.observed_apex_mail {
        let expected = normalized(observed);
        if !records.iter().any(|record| {
            let actual = normalized(record);
            expected
                .as_object()
                .is_some_and(|fields| fields.iter().all(|(k, v)| actual.get(k) == Some(v)))
        }) {
            return Err(error("public_mail_export_mismatch"));
        }
    }
    let retired = if retire_mail {
        records
            .iter()
            .filter(|r| unused_mail_record(r))
            .cloned()
            .collect()
    } else {
        vec![]
    };
    let preserve = records
        .iter()
        .filter(|r| {
            !(r["name"] == source.domain
                && matches!(r["type"].as_str(), Some("A" | "AAAA" | "CNAME")))
                && !(retire_mail && unused_mail_record(r))
        })
        .cloned()
        .collect();
    let add = if retire_mail {
        serde_json::to_value(dns_import::parse(
            &source.domain,
            source.ttl,
            "mx . 0\ntxt @ \"v=spf1 -all\"\ntxt _dmarc \"v=DMARC1; p=reject;\"",
        )?)
        .map_err(|_| error("invalid_dns"))?
        .as_array()
        .ok_or_else(|| error("invalid_dns"))?
        .clone()
    } else {
        vec![]
    };
    Ok((preserve, retired, add))
}
fn unused_mail_record(record: &Value) -> bool {
    let kind = record["type"].as_str().unwrap_or("");
    let name = record["name"].as_str().unwrap_or("").to_lowercase();
    let text = record["content"]
        .as_str()
        .unwrap_or("")
        .trim_matches('"')
        .to_lowercase();
    kind == "MX"
        || (matches!(kind, "TXT" | "CNAME")
            && (name.contains("._domainkey.")
                || (kind == "TXT"
                    && (text.starts_with("v=spf1")
                        || text.starts_with("v=dmarc1")
                        || text.starts_with("v=dkim1")
                        || text.starts_with("v=stsv1")))))
}
/// Hash approvals are accepted only for plans issued in this live scoped session.
pub struct Session {
    domain: String,
    account: String,
    issued: BTreeMap<String, Plan>,
    allow_empty_unserved: bool,
    retire_unused_mail: bool,
}
impl Session {
    pub fn new(domain: &str, account: &str) -> Result<Self> {
        if !valid_id(account) {
            return Err(error("invalid_account"));
        }
        Ok(Self {
            domain: domain_name(domain)?,
            account: account.into(),
            issued: BTreeMap::new(),
            allow_empty_unserved: false,
            retire_unused_mail: false,
        })
    }
    pub fn allow_empty_registered_unserved(mut self) -> Self {
        self.allow_empty_unserved = true;
        self
    }
    pub fn retire_unused_mail(mut self) -> Self {
        self.retire_unused_mail = true;
        self
    }
    fn observed_source(
        &self,
        registrar: &mut impl ReadTransport,
        public: &mut impl ReadTransport,
    ) -> Result<Source> {
        match source(registrar, public, &self.domain) {
            Err(failure) if self.allow_empty_unserved && failure.code == "dns_servfail" => {
                crate::empty_registered_source::source(registrar, public, &self.domain)
            }
            result => result,
        }
    }
    pub fn observe(
        &self,
        registrar: &mut impl ReadTransport,
        dns: &mut impl ReadTransport,
        public: &mut impl ReadTransport,
    ) -> Result<Value> {
        Ok(
            json!({"source":self.observed_source(registrar,public)?,"zone":zone_state(dns,&self.account,&self.domain)?,"writes_performed":false}),
        )
    }
    pub fn plan(
        &mut self,
        phase: &str,
        registrar: &mut impl ReadTransport,
        dns: &mut impl ReadTransport,
        public: &mut impl ReadTransport,
    ) -> Result<Value> {
        if !matches!(phase, "prepare_zone" | "change_nameservers") {
            return Err(error("invalid_phase"));
        }
        let source = self.observed_source(registrar, public)?;
        let zone = zone_state(dns, &self.account, &self.domain)?;
        if source.source_mode == SourceMode::EmptyRegisteredUnserved
            && zone
                .as_ref()
                .is_some_and(|current| !current.records.is_empty())
        {
            return Err(error("empty_target_zone_required"));
        }
        let (records_to_preserve, records_to_retire, records_to_add) =
            desired(&source, self.retire_unused_mail)?;
        if self.retire_unused_mail
            && zone
                .as_ref()
                .is_some_and(|z| z.records.iter().any(unused_mail_record))
        {
            // Existing target mail is a separate destructive action; never delete it here.
            // Exact no-mail declarations from this plan are allowed on re-observation.
            let z = zone.as_ref().ok_or_else(|| error("zone_not_prepared"))?;
            if z.records
                .iter()
                .filter(|r| unused_mail_record(r))
                .any(|r| !contains_record(&records_to_add, r))
            {
                return Err(error("target_mail_retirement_requires_review"));
            }
        }
        if phase == "change_nameservers" {
            if source.parent_ds_present {
                return Err(error("dnssec_transition_required"));
            }
            let z = zone.as_ref().ok_or_else(|| error("zone_not_prepared"))?;
            if !records_to_preserve
                .iter()
                .chain(records_to_add.iter())
                .all(|r| contains_record(&z.records, r))
            {
                return Err(error("dns_copy_not_verified"));
            }
        }
        let created_at = now()?;
        let mut nonce = [0_u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut nonce))
            .map_err(|_| error("nonce_failed"))?;
        let plan = Plan {
            implementation_version: env!("CARGO_PKG_VERSION").into(),
            implementation_source_sha: option_env!("ZIXCEL_DOMAIN_SOURCE_SHA").map(str::to_owned),
            phase: phase.into(),
            domain: self.domain.clone(),
            account: self.account.clone(),
            source,
            zone,
            records_to_preserve,
            records_to_retire,
            records_to_add,
            retire_unused_mail: self.retire_unused_mail,
            created_at,
            expires_at: created_at + 600,
            nonce: nonce.iter().map(|x| format!("{x:02x}")).collect(),
        };
        if serde_json::to_vec(&plan)
            .map_err(|_| error("invalid_plan"))?
            .len()
            > 900 * 1024
        {
            return Err(error("plan_byte_budget"));
        }
        let hash = digest(&plan)?;
        if self.issued.len() >= 20 {
            return Err(error("plan_budget"));
        }
        self.issued.insert(hash.clone(), plan.clone());
        Ok(json!({"plan":plan,"sha256":hash,"writes_performed":false}))
    }
    pub fn apply(
        &mut self,
        approval: &str,
        registrar: &mut impl WriteTransport,
        dns: &mut impl WriteTransport,
        public: &mut impl ReadTransport,
    ) -> Result<Value> {
        let plan = self
            .issued
            .remove(approval)
            .ok_or_else(|| error("unissued_or_consumed_plan"))?;
        if now()? >= plan.expires_at || digest(&plan)? != approval {
            return Err(error("expired_or_modified_plan"));
        }
        if self.observed_source(registrar, public)? != plan.source
            || zone_state(dns, &self.account, &self.domain)? != plan.zone
        {
            return Err(error("snapshot_drift"));
        }
        if now()? >= plan.expires_at {
            return Err(error("expired_or_modified_plan"));
        }
        let mut writes = 0;
        let result = self.perform(&plan, registrar, dns, &mut writes);
        match result {
            Ok(value) => Ok(
                json!({"phase":plan.phase,"domain":self.domain,"plan_sha256":approval,"writes_attempted":writes,"status":"provider_verified","result":value}),
            ),
            Err(e) => Ok(
                json!({"phase":plan.phase,"domain":self.domain,"plan_sha256":approval,"writes_attempted":writes,"status":if writes == 0 {"rejected"} else {"partial_or_unknown"},"error":e,"blind_replay_allowed":false}),
            ),
        }
    }
    fn perform(
        &self,
        plan: &Plan,
        registrar: &mut impl WriteTransport,
        dns: &mut impl WriteTransport,
        writes: &mut usize,
    ) -> Result<Value> {
        if plan.phase == "prepare_zone" {
            let mut zone = if let Some(z) = &plan.zone {
                z.clone()
            } else {
                if now()? >= plan.expires_at {
                    return Err(error("expired_or_modified_plan"));
                }
                *writes += 1;
                let response = dns.post(
                    "/zones",
                    &json!({"name":self.domain,"account":{"id":self.account},"type":"full"}),
                )?;
                let z = &response["result"];
                if response["success"] != true
                    || z["name"] != self.domain
                    || z["account"]["id"] != self.account
                {
                    return Err(error("zone_creation_not_verified"));
                }
                zone_state(dns, &self.account, &self.domain)?
                    .ok_or_else(|| error("zone_creation_not_observed"))?
            };
            // Reject incompatible existing RRsets before any record additions.
            for desired in plan
                .records_to_preserve
                .iter()
                .chain(plan.records_to_add.iter())
            {
                if !contains_record(&zone.records, desired)
                    && !matches!(desired["type"].as_str(), Some("MX" | "TXT"))
                    && zone
                        .records
                        .iter()
                        .any(|r| r["type"] == desired["type"] && r["name"] == desired["name"])
                {
                    return Err(error("record_conflict"));
                }
            }
            let original = zone.records.clone();
            for record in plan
                .records_to_preserve
                .iter()
                .chain(plan.records_to_add.iter())
            {
                if contains_record(&zone.records, record) {
                    continue;
                }
                if now()? >= plan.expires_at {
                    return Err(error("expired_or_modified_plan"));
                }
                *writes += 1;
                let response = dns.post(&format!("/zones/{}/dns_records", zone.id), record)?;
                if response["success"] != true {
                    return Err(error("record_write_rejected"));
                }
                zone.records.push(record.clone());
            }
            let observed = cloudflare::records(dns, &zone.id)?;
            if !plan
                .records_to_preserve
                .iter()
                .chain(plan.records_to_add.iter())
                .all(|r| contains_record(&observed, r))
                || !original.iter().all(|r| contains_record(&observed, r))
            {
                return Err(error("dns_readback_mismatch"));
            }
            Ok(
                json!({"zone_id":zone.id,"cloudflare_nameservers":zone.nameservers,"preserved_records":plan.records_to_preserve.len(),"added_records":plan.records_to_add.len(),"retired_mail_records":plan.records_to_retire.len(),"retire_unused_mail":plan.retire_unused_mail,"registrar_nameservers_changed":false,"apex_web_records_excluded":true}),
            )
        } else {
            let zone = plan
                .zone
                .as_ref()
                .ok_or_else(|| error("zone_not_prepared"))?;
            if plan.source.parent_ds_present {
                return Err(error("dnssec_transition_required"));
            }
            if plan.source.registrar_nameservers != zone.nameservers {
                if now()? >= plan.expires_at {
                    return Err(error("expired_or_modified_plan"));
                }
                *writes += 1;
                registrar.put(
                    &format!("/domains/{}/nameserver", self.domain),
                    &json!({"ns":zone.nameservers}),
                )?;
            }
            let observed = sorted(valuedomain::nameservers(registrar, &self.domain)?);
            if observed != zone.nameservers {
                return Err(error("nameserver_readback_mismatch"));
            }
            Ok(
                json!({"registrar_nameservers":observed,"public_propagation":"pending_separate_verification","zone_id":zone.id}),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Never;
    impl ReadTransport for Never {
        fn get(&mut self, _: &str) -> Result<Value> {
            panic!("expired approval must not access provider")
        }
    }
    impl WriteTransport for Never {
        fn post(&mut self, _: &str, _: &Value) -> Result<Value> {
            panic!("unexpected write")
        }
        fn put(&mut self, _: &str, _: &Value) -> Result<Value> {
            panic!("unexpected write")
        }
    }
    #[test]
    fn expired_issued_plan_is_rejected_and_consumed_before_any_provider_access() {
        let account = "00000000000000000000000000000001";
        let mut session = Session::new("example.test", account).unwrap();
        let plan = Plan {
            implementation_version: env!("CARGO_PKG_VERSION").into(),
            implementation_source_sha: None,
            phase: "prepare_zone".into(),
            domain: "example.test".into(),
            account: account.into(),
            source: Source {
                source_mode: SourceMode::RegisteredAndPublicObserved,
                domain: "example.test".into(),
                registrar_nameservers: vec![],
                public_nameservers: vec![],
                parent_delegation_nameservers: vec![],
                public_soa: "".into(),
                dns_service: "valuedomain1".into(),
                records: "".into(),
                ttl: 3600,
                parent_ds_present: false,
                observed_apex_mail: vec![],
            },
            zone: None,
            records_to_preserve: vec![],
            records_to_retire: vec![],
            records_to_add: vec![],
            retire_unused_mail: false,
            created_at: 0,
            expires_at: 0,
            nonce: "fixture".into(),
        };
        let hash = digest(&plan).unwrap();
        session.issued.insert(hash.clone(), plan);
        assert_eq!(
            session
                .apply(&hash, &mut Never, &mut Never, &mut Never)
                .unwrap_err()
                .code,
            "expired_or_modified_plan"
        );
        assert_eq!(
            session
                .apply(&hash, &mut Never, &mut Never, &mut Never)
                .unwrap_err()
                .code,
            "unissued_or_consumed_plan"
        );
    }
}
