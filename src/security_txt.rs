//! Bounded RFC 9116 field checks; no signature, mailbox ownership or response promise is inferred.
use crate::{Result, domain_name, error};
use serde_json::{Value, json};
pub fn inspect(text: &str, domain: &str, now: u64) -> Result<Value> {
    let domain = domain_name(domain)?;
    if text.len() > 32768
        || text.lines().count() > 1000
        || text.lines().any(|l| l.len() > 2048)
        || text.contains('\0')
    {
        return Err(error("securitytxt_budget"));
    }
    if text.starts_with("-----BEGIN PGP") {
        return Err(error("signed_securitytxt_requires_verified_extraction"));
    }
    let mut contacts = Vec::new();
    let mut expires = None;
    let mut canonical = Vec::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| error("invalid_securitytxt_field"))?;
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "contact" => {
                let uri =
                    reqwest::Url::parse(value).map_err(|_| error("invalid_security_contact"))?;
                if !["https", "mailto", "tel"].contains(&uri.scheme())
                    || !uri.username().is_empty()
                    || uri.password().is_some()
                    || uri.fragment().is_some()
                    || (uri.scheme() == "https" && uri.host_str().is_none())
                    || (uri.scheme() == "mailto" && !uri.path().contains('@'))
                {
                    return Err(error("invalid_security_contact"));
                }
                contacts.push(value.to_owned());
            }
            "expires" => {
                if expires.is_some() {
                    return Err(error("duplicate_securitytxt_expiry"));
                }
                let timestamp = chrono::DateTime::parse_from_rfc3339(value)
                    .map_err(|_| error("invalid_securitytxt_expiry"))?
                    .timestamp();
                if timestamp < 0 || timestamp as u64 <= now {
                    return Err(error("expired_securitytxt"));
                }
                expires = Some(timestamp as u64);
            }
            "canonical" => canonical.push(value.to_owned()),
            _ => {}
        }
    }
    if contacts.is_empty() || expires.is_none() {
        return Err(error("required_securitytxt_field_missing"));
    }
    let uri = format!("https://{domain}/.well-known/security.txt");
    if !canonical.is_empty() && !canonical.contains(&uri) {
        return Err(error("securitytxt_canonical_mismatch"));
    }
    Ok(
        json!({"syntax_profile":"RFC9116-fields","contacts":contacts,"expires":expires,
        "canonical_matches":canonical.contains(&uri),"signature_verified":false,
        "contact_delivery_verified":false,"authorization_to_test_granted":false}),
    )
}
