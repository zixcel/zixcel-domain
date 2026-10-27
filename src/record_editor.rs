//! Single-record Cloudflare plans. Inspect locally; hashes authorize only an issued plan.
pub use crate::record_change::Edit;
pub use crate::record_data::{RecordData, RecordType};
pub use crate::record_execution::{Receipt, ReceiptState};
pub use crate::record_snapshot::{Scope, Snapshot};
use crate::transport::{ReadTransport, RecordWriteTransport};
use crate::{Result, approval, domain_release::digest, error, record_execution, record_snapshot};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordPlan {
    pub implementation_version: String,
    pub implementation_source_sha: Option<String>,
    pub scope: Scope,
    pub before: Snapshot,
    pub edit: Edit,
    pub created_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}
#[derive(Debug, Serialize)]
pub struct PlannedEdit {
    pub plan: RecordPlan,
    pub sha256: String,
}
struct Issued {
    plan: RecordPlan,
    hash: String,
    deadline: Instant,
}
pub struct Editor {
    scope: Scope,
    issued: Option<Issued>,
}
impl Editor {
    pub fn new(scope: Scope) -> Result<Self> {
        Ok(Self {
            scope: scope.validate()?,
            issued: None,
        })
    }
    /// Replaces any previously issued plan; does not write to the provider.
    pub fn plan(&mut self, edit: Edit, transport: &mut impl ReadTransport) -> Result<PlannedEdit> {
        self.issued = None;
        let edit = edit.normalize(&self.scope)?;
        let before = record_snapshot::read(transport, &self.scope)?;
        edit.validate(&before)?;
        crate::dmarc::edit::validate(&self.scope, &before, &edit)?;
        let created_at = approval::now()?;
        let plan = RecordPlan {
            implementation_version: env!("CARGO_PKG_VERSION").into(),
            implementation_source_sha: option_env!("ZIXCEL_DOMAIN_SOURCE_SHA").map(str::to_owned),
            scope: self.scope.clone(),
            before,
            edit,
            created_at,
            expires_at: created_at
                .checked_add(300)
                .ok_or_else(|| error("invalid_clock"))?,
            nonce: approval::nonce()?,
        };
        let hash = digest(&plan)?;
        self.issued = Some(Issued {
            plan: plan.clone(),
            hash: hash.clone(),
            deadline: Instant::now() + Duration::from_secs(300),
        });
        Ok(PlannedEdit { plan, sha256: hash })
    }
    /// Consumes approval before any provider read/write; failures never restore it.
    pub fn apply(
        &mut self,
        hash: &str,
        transport: &mut impl RecordWriteTransport,
    ) -> Result<Receipt> {
        let issued = self
            .issued
            .take()
            .ok_or_else(|| error("unissued_or_consumed_plan"))?;
        if hash != issued.hash || digest(&issued.plan)? != hash {
            return Err(error("unissued_or_modified_plan"));
        }
        let expired = || -> Result<bool> {
            Ok(approval::now()? >= issued.plan.expires_at || Instant::now() >= issued.deadline)
        };
        if expired()? {
            return Err(error("expired_plan"));
        }
        if record_snapshot::read(transport, &self.scope)? != issued.plan.before {
            return Err(error("snapshot_drift"));
        }
        if expired()? {
            return Err(error("expired_plan"));
        }
        Ok(record_execution::execute(&issued.plan, hash, transport))
    }
}
#[cfg(test)]
#[path = "record_editor_tests.rs"]
mod tests;

/// Detached native operation. The caller owns terminal approval and durable one-use admission.
/// Reuses the same record, DMARC, complete snapshot and readback checks as the session.
pub fn apply_reviewed(
    plan: &RecordPlan,
    transport: &mut impl RecordWriteTransport,
) -> Result<Receipt> {
    if plan.implementation_version != env!("CARGO_PKG_VERSION")
        || plan.created_at > approval::now()?
        || plan.expires_at != plan.created_at.saturating_add(300)
        || approval::now()? >= plan.expires_at
    {
        return Err(error("expired_or_modified_plan"));
    }
    let scope = plan.scope.clone().validate()?;
    if scope != plan.scope {
        return Err(error("invalid_scope"));
    }
    let edit = plan.edit.clone().normalize(&scope)?;
    if serde_json::to_value(&edit).ok() != serde_json::to_value(&plan.edit).ok() {
        return Err(error("invalid_plan"));
    }
    let before = record_snapshot::read(transport, &scope)?;
    if before != plan.before {
        return Err(error("snapshot_drift"));
    }
    edit.validate(&before)?;
    crate::dmarc::edit::validate(&scope, &before, &edit)?;
    if approval::now()? >= plan.expires_at {
        return Err(error("expired_plan"));
    }
    Ok(record_execution::execute(plan, &digest(plan)?, transport))
}
pub fn snapshot(scope: Scope, transport: &mut impl ReadTransport) -> Result<Snapshot> {
    record_snapshot::read(transport, &scope.validate()?)
}

/// Read-only verification of a historical acknowledged write. Does not renew its approval.
pub fn verify_observed(plan: &RecordPlan, id: &str, after: &Snapshot) -> Result<()> {
    if !crate::valid_id(id)
        || plan.scope.clone().validate()? != plan.scope
        || plan.expires_at != plan.created_at.saturating_add(300)
        || plan.before.zone != after.zone
        || plan.edit.id().is_some_and(|expected| expected != id)
        || (plan.edit.id().is_none() && plan.before.records.iter().any(|v| v["id"] == id))
    {
        return Err(error("invalid_resolution_original"));
    }
    let normalized = plan.edit.clone().normalize(&plan.scope)?;
    if serde_json::to_value(&normalized).ok() != serde_json::to_value(&plan.edit).ok() {
        return Err(error("invalid_resolution_original"));
    }
    normalized.validate(&plan.before)?;
    crate::dmarc::edit::validate(&plan.scope, &plan.before, &normalized)?;
    record_execution::verify_snapshot(plan, id, after)
}
