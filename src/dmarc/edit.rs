use crate::{
    Result, error,
    record_change::Edit,
    record_data::RecordType,
    record_snapshot::{Scope, Snapshot},
};
pub(crate) fn validate(scope: &Scope, snapshot: &Snapshot, edit: &Edit) -> Result<()> {
    let (id, record) = match edit {
        Edit::Create { record } => (None, record),
        Edit::Update { record_id, record } => (Some(record_id.as_str()), record),
        Edit::Delete { .. } => return Ok(()),
    };
    if record.kind != RecordType::TXT || !record.name.starts_with("_dmarc.") {
        return Ok(());
    }
    if record.proxied
        || !(record.name == format!("_dmarc.{}", scope.domain)
            || record.name.ends_with(&format!(".{}", scope.domain)))
    {
        return Err(error("invalid_dmarc_owner"));
    }
    super::parse(std::slice::from_ref(&record.content))?;
    for row in &snapshot.records {
        if row["type"] == "TXT"
            && row["name"] == record.name
            && !id.is_some_and(|id| row["id"] == id)
            && row["content"]
                .as_str()
                .is_some_and(|v| v.trim_start().starts_with("v=DMARC1"))
        {
            return Err(error("dmarc_consolidation_requires_explicit_review"));
        }
    }
    Ok(())
}
