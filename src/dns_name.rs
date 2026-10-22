//! DNS service labels are not hostnames or registrar ownership identifiers.
use crate::{Result, domain_name, error};
pub fn record_name(value: &str) -> Result<String> {
    if !value.contains('_') {
        return domain_name(value);
    }
    // A DNS service label can follow a selector, not only prefix the name.
    // Validate each service label wherever it occurs. Host labels still pass
    // the existing hostname parser, so this is not a relaxed URL validator.
    if !value.is_ascii() || value.len() > 254 {
        return Err(error("invalid_dns_owner"));
    }
    let name = value.trim_end_matches('.').to_ascii_lowercase();
    if name.len() > 253 {
        return Err(error("invalid_dns_owner"));
    }
    let mut host_labels = Vec::new();
    for label in name.split('.') {
        if let Some(service) = label.strip_prefix('_') {
            if service.is_empty()
                || label.len() > 63
                || label.ends_with('-')
                || !service
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(error("invalid_dns_owner"));
            }
            host_labels.push("s");
        } else {
            host_labels.push(label);
        }
    }
    domain_name(&host_labels.join("."))?;
    Ok(name)
}
