//! Reconcile an acknowledged Cloudflare write using complete reads only.
use super::super::*;
use zixcel_domain::record_editor::{Snapshot, verify_observed};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Resolution {
    pub(super) profile: Profile,
    pub(super) profile_sha256: String,
    pub(super) original_plan_file: String,
    pub(super) original_sha256: String,
    pub(super) record_id: String,
    pub(super) observation: Snapshot,
    pub(super) created_at: u64,
    pub(super) expires_at: u64,
}
pub(super) fn original(
    path: &str,
    profile: &Profile,
    profile_hash: &str,
) -> Result<(String, RecordPlan), Error> {
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
    let p: RecordPlan = decode(payload.change)?;
    let Target::Cloudflare { account, zone } = &profile.target else {
        return Err(Error("unsupported_resolution_target"));
    };
    if p.scope
        != (Scope {
            domain: profile.domain.clone(),
            account: account.clone(),
            zone: zone.clone(),
        })
    {
        return Err(Error("resolution_scope_mismatch"));
    }
    Ok((hash, p))
}
pub(super) fn acknowledged(profile: &Profile, hash: &str, p: &RecordPlan) -> Result<String, Error> {
    let journal = Journal::open(Path::new(&profile.journal_directory))?;
    journal.pending(hash, &profile.domain)?;
    let path = Path::new(&profile.journal_directory).join(format!("{hash}.receipt"));
    let receipt: Value = read(path.to_str().ok_or(Error("invalid_path"))?)?;
    if receipt["plan_sha256"]
        != zixcel_domain::domain_release::digest(p).map_err(|_| Error("invalid_original_plan"))?
        || receipt["blind_replay_allowed"] != false
    {
        return Err(Error("resolution_original_receipt_mismatch"));
    }
    let id = receipt["record_id"]
        .as_str()
        .ok_or(Error("unacknowledged_write_cannot_resolve"))?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error("invalid_record_id"));
    }
    Ok(id.into())
}
pub(super) fn observe(p: &RecordPlan, id: &str, deadline: Instant) -> Result<Snapshot, Failure> {
    let mut t = http(Provider::Cloudflare, deadline)?;
    let first = record_editor::snapshot(p.scope.clone(), &mut t).map_err(fail)?;
    verify_observed(p, id, &first).map_err(fail)?;
    let second = record_editor::snapshot(p.scope.clone(), &mut t).map_err(fail)?;
    if first != second {
        return Err(Error("resolution_snapshot_drift").into());
    }
    Ok(second)
}
pub(super) fn now() -> Result<u64, Error> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error("clock_unavailable"))?
        .as_secs())
}

#[cfg(test)]
#[path = "cloudflare_tests.rs"]
mod tests;
