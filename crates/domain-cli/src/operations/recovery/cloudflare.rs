//! Read-only Cloudflare reconciliation plans and local journal transitions.
use super::*;
#[path = "cloudflare_support.rs"]
mod support;
use support::{Resolution, acknowledged, now, observe, original};
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
    if r.operation == "dns.records.resolve.plan" {
        let path = arg("original-plan-file")?;
        let (hash, p) = original(path, &profile, &profile_hash)?;
        let id = acknowledged(&profile, &hash, &p)?;
        let observation = observe(&p, &id, deadline)?;
        let time = now()?;
        let plan = LocalPlan::new(
            "dns.records.resolve.apply".into(),
            binding()?,
            encoded(Resolution {
                profile,
                profile_sha256: profile_hash,
                original_plan_file: path.into(),
                original_sha256: hash,
                record_id: id,
                observation,
                created_at: time,
                expires_at: time.saturating_add(300),
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
    let time = now()?;
    if resolution.profile != profile
        || resolution.profile_sha256 != profile_hash
        || arg("journal-directory")? != profile.journal_directory
    {
        return Err(Error("resolution_scope_mismatch").into());
    }
    if resolution.created_at > time
        || resolution.expires_at != resolution.created_at.saturating_add(300)
        || time >= resolution.expires_at
    {
        return Err(Error("expired_resolution_plan").into());
    }
    let (hash, p) = original(&resolution.original_plan_file, &profile, &profile_hash)?;
    if hash != resolution.original_sha256 {
        return Err(Error("original_plan_changed").into());
    }
    let id = acknowledged(&profile, &hash, &p)?;
    if id != resolution.record_id {
        return Err(Error("resolution_original_receipt_mismatch").into());
    }
    let current = observe(&p, &id, deadline)?;
    if current != resolution.observation {
        return Err(Error("resolution_snapshot_drift").into());
    }
    let receipt = json!({"schema":"zix-domain-dns-resolution/v1","original_plan_sha256":hash,
        "approved_resolution_sha256":arg("approval-sha256")?,"original_outcome":"unknown",
        "original_replay_allowed":false,"remote_write_attempted":false,"provider":"cloudflare",
        "record_id":id,"observation":current,"state":"recorded"});
    if now()? >= resolution.expires_at {
        return Err(Error("expired_resolution_plan").into());
    }
    Journal::open(Path::new(&profile.journal_directory))?.resolve(
        &hash,
        &profile.domain,
        &receipt,
    )?;
    Ok(receipt)
}
