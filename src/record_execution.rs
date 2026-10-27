use crate::{
    Error, Result, error,
    record_change::{Edit, metadata},
    record_editor::RecordPlan,
    record_snapshot,
    transport::RecordWriteTransport,
    valid_id,
};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    ProviderVerified,
    OutcomeUnknown,
}
#[derive(Debug, Serialize)]
pub struct Receipt {
    pub plan_sha256: String,
    pub state: ReceiptState,
    pub writes_attempted: u8,
    pub record_id: Option<String>,
    pub error: Option<Error>,
    pub blind_replay_allowed: bool,
}
fn write(plan: &RecordPlan, transport: &mut impl RecordWriteTransport) -> Result<String> {
    let path = plan.edit.path(&plan.scope);
    let response = match &plan.edit {
        Edit::Create { record } => transport.post(&path, &record.body()?)?,
        Edit::Update { record, .. } => transport.patch(&path, &record.body()?)?,
        Edit::Delete { .. } => transport.delete(&path)?,
    };
    let id = response["result"]["id"]
        .as_str()
        .ok_or_else(|| error("invalid_write_result"))?;
    if response["success"] != true
        || !valid_id(id)
        || plan.edit.id().is_some_and(|expected| expected != id)
        || (plan.edit.id().is_none() && plan.before.records.iter().any(|v| v["id"] == id))
    {
        return Err(error("invalid_write_result"));
    }
    Ok(id.into())
}
fn verify(plan: &RecordPlan, id: &str, transport: &mut impl RecordWriteTransport) -> Result<()> {
    let after = record_snapshot::read(transport, &plan.scope)?;
    verify_snapshot(plan, id, &after)
}
pub(crate) fn verify_snapshot(
    plan: &RecordPlan,
    id: &str,
    after: &record_snapshot::Snapshot,
) -> Result<()> {
    let without = |records: &[Value]| {
        records
            .iter()
            .filter(|v| v["id"] != id)
            .cloned()
            .collect::<Vec<_>>()
    };
    if after.zone != plan.before.zone || without(&after.records) != without(&plan.before.records) {
        return Err(error("readback_drift"));
    }
    let target = after.records.iter().find(|v| v["id"] == id);
    match &plan.edit {
        Edit::Delete { .. } if target.is_none() => Ok(()),
        Edit::Create { record } if target.is_some_and(|v| record.matches(v).unwrap_or(false)) => {
            Ok(())
        }
        Edit::Update { record, .. }
            if target.is_some_and(|v| record.matches(v).unwrap_or(false)) =>
        {
            let original = plan
                .before
                .records
                .iter()
                .find(|v| v["id"] == id)
                .ok_or_else(|| error("record_missing"))?;
            if metadata(original) == metadata(target.ok_or_else(|| error("record_missing"))?) {
                Ok(())
            } else {
                Err(error("record_metadata_changed"))
            }
        }
        _ => Err(error("readback_mismatch")),
    }
}
pub(crate) fn execute(
    plan: &RecordPlan,
    hash: &str,
    transport: &mut impl RecordWriteTransport,
) -> Receipt {
    let mut record_id = None;
    let result = write(plan, transport).and_then(|id| {
        record_id = Some(id.clone());
        verify(plan, &id, transport)
    });
    Receipt {
        plan_sha256: hash.into(),
        state: if result.is_ok() {
            ReceiptState::ProviderVerified
        } else {
            ReceiptState::OutcomeUnknown
        },
        writes_attempted: 1,
        record_id,
        error: result.err(),
        blind_replay_allowed: false,
    }
}
