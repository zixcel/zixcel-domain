//! Local registrar/DNS inventory. Credentials never enter the inventory model.
mod approval;
pub mod cloudflare;
pub mod delegation;
pub mod dns_import;
pub mod domain_release;
#[cfg(unix)]
pub mod domain_session;
mod empty_registered_source;
pub mod inspection;
pub mod mapping;
pub mod native;
pub mod public_dns;
mod record_change;
pub mod record_cli;
mod record_data;
pub mod record_editor;
mod record_execution;
mod record_http;
mod record_snapshot;
pub mod transport;
pub mod valuedomain;

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Error {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
}
impl Error {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            provider: None,
            operation: None,
            http_status: None,
        }
    }
    pub fn with_context(mut self, provider: &'static str, operation: &'static str) -> Self {
        self.provider = Some(provider);
        self.operation = Some(operation);
        self
    }
    pub fn for_operation(mut self, operation: &'static str) -> Self {
        self.operation = Some(operation);
        self
    }
    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Error {}
pub(crate) fn error(code: &'static str) -> Error {
    Error::new(code)
}

/// Canonical ASCII DNS name; inputs cannot introduce URL paths or queries.
pub fn domain_name(input: &str) -> Result<String> {
    let name = idna::domain_to_ascii_strict(input.trim_end_matches('.'))
        .map_err(|_| error("invalid_domain"))?
        .to_lowercase();
    if name.len() > 253
        || !name.contains('.')
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(error("invalid_domain"));
    }
    Ok(name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainBinding {
    pub organization: String,
    pub domain: String,
    pub cloudflare_account_id: String,
}

/// Organization ownership comes from an explicit manifest, never from provider guesses.
pub fn validate_bindings(bindings: &[DomainBinding]) -> Result<()> {
    if bindings.len() > 1000 {
        return Err(error("binding_budget"));
    }
    let mut seen = BTreeSet::new();
    for binding in bindings {
        if binding.organization.is_empty()
            || binding.organization.len() > 100
            || !binding
                .organization
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !valid_id(&binding.cloudflare_account_id)
        {
            return Err(error("invalid_binding"));
        }
        let name = domain_name(&binding.domain)?;
        if !seen.insert(name) {
            return Err(error("duplicate_domain"));
        }
    }
    Ok(())
}

pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
