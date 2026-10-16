//! Single-record Cloudflare plans. Inspect locally; hashes authorize only an issued plan.
pub use crate::record_change::Edit;
pub use crate::record_data::{RecordData, RecordType};
pub use crate::record_execution::{Receipt, ReceiptState};
pub use crate::record_snapshot::{Scope, Snapshot};
use crate::transport::{ReadTransport, RecordWriteTransport};
use crate::{Result, approval, domain_release::digest, error, record_execution, record_snapshot};
use serde::Serialize;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize)]
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
