use crate::{Result, dns_import, domain_name, error};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    TXT,
    MX,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordData {
    #[serde(rename = "type")]
    pub kind: RecordType,
    /// Absolute ASCII/Punycode DNS owner, including the zone suffix.
    pub name: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}
impl RecordData {
    pub(crate) fn normalize(mut self, domain: &str) -> Result<Self> {
        self.name = dns_import::owner(domain, &format!("{}.", self.name.trim_end_matches('.')))?;
        if !(self.ttl == 1 || (60..=86400).contains(&self.ttl))
            || self.content.is_empty()
            || self.content.len() > 2048
            || self.content.chars().any(char::is_control)
            || (self.kind == RecordType::MX) != self.priority.is_some()
            || (self.proxied
                && (matches!(self.kind, RecordType::TXT | RecordType::MX) || self.ttl != 1))
        {
            return Err(error("invalid_record_data"));
        }
        self.content = match self.kind {
            RecordType::A => self
                .content
                .parse::<Ipv4Addr>()
                .map_err(|_| error("invalid_address"))?
                .to_string(),
            RecordType::AAAA => self
                .content
                .parse::<Ipv6Addr>()
                .map_err(|_| error("invalid_address"))?
                .to_string(),
            RecordType::CNAME | RecordType::MX => domain_name(&self.content)?,
            RecordType::TXT => self.content,
        };
        if self.kind == RecordType::CNAME && self.content == self.name {
            return Err(error("cname_self_reference"));
        }
        Ok(self)
    }
    pub(crate) fn body(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|_| error("invalid_record_data"))
    }
    pub(crate) fn matches(&self, value: &Value) -> Result<bool> {
        Ok(self
            .body()?
            .as_object()
            .ok_or_else(|| error("invalid_record_data"))?
            .iter()
            .all(|(key, wanted)| value.get(key) == Some(wanted)))
    }
}
