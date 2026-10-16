use crate::{
    Result, error,
    record_data::RecordData,
    record_snapshot::{Scope, Snapshot},
    valid_id,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Edit {
    Create {
        record: RecordData,
    },
    Update {
        record_id: String,
        record: RecordData,
    },
    Delete {
        record_id: String,
    },
}
impl Edit {
    pub(crate) fn id(&self) -> Option<&str> {
        match self {
            Self::Create { .. } => None,
            Self::Update { record_id, .. } | Self::Delete { record_id } => Some(record_id),
        }
    }
    pub(crate) fn desired(&self) -> Option<&RecordData> {
        match self {
            Self::Create { record } | Self::Update { record, .. } => Some(record),
            Self::Delete { .. } => None,
        }
    }
    pub(crate) fn normalize(self, scope: &Scope) -> Result<Self> {
        if self.id().is_some_and(|v| !valid_id(v)) {
            return Err(error("invalid_record_id"));
        }
        Ok(match self {
            Self::Create { record } => Self::Create {
                record: record.normalize(&scope.domain)?,
            },
            Self::Update { record_id, record } => Self::Update {
                record_id,
                record: record.normalize(&scope.domain)?,
            },
            Self::Delete { record_id } => Self::Delete { record_id },
        })
    }
    pub(crate) fn validate(&self, snapshot: &Snapshot) -> Result<()> {
        if let Some(id) = self.id() {
            let before = snapshot
                .records
                .iter()
                .find(|v| v["id"] == id)
                .ok_or_else(|| error("record_missing"))?;
            if !["A", "AAAA", "CNAME", "TXT", "MX"]
                .iter()
                .any(|t| before["type"] == *t)
            {
                return Err(error("unsupported_record_type"));
            }
            if let Some(record) = self.desired() {
                if before["type"] != record.body()?["type"] {
                    return Err(error("record_type_change_refused"));
                }
                if record.matches(before)? {
                    return Err(error("record_unchanged"));
                }
            }
        }
        if let Some(record) = self.desired() {
            let desired = record.body()?;
            for other in &snapshot.records {
                if self.id().is_some_and(|id| other["id"] == id) || other["name"] != record.name {
                    continue;
                }
                if desired["type"] == "CNAME" || other["type"] == "CNAME" || other["type"] == "NS" {
                    return Err(error("record_name_conflict"));
                }
                if other["type"] == desired["type"]
                    && other["content"] == desired["content"]
                    && (desired["type"] != "MX" || other["priority"] == desired["priority"])
                {
                    return Err(error("duplicate_record"));
                }
            }
        }
        Ok(())
    }
    pub(crate) fn path(&self, scope: &Scope) -> String {
        match self.id() {
            Some(id) => format!("{}/{id}", scope.records_path()),
            None => scope.records_path(),
        }
    }
}
pub(crate) fn metadata(value: &Value) -> Value {
    let mut copy = value.clone();
    if let Some(object) = copy.as_object_mut() {
        for key in [
            "name",
            "content",
            "ttl",
            "proxied",
            "priority",
            "modified_on",
        ] {
            object.remove(key);
        }
    }
    copy
}
