//! DNS service labels are not hostnames or registrar ownership identifiers.
use crate::{Result, domain_name, error};
pub fn record_name(value: &str) -> Result<String> {
    if !value.contains('_') {
        return domain_name(value);
    }
    // A DNS service label can follow a selector, not only prefix the name.
    // Validate each service label wherever it occurs. Host labels still pass
    // the existing hostname parser, so this is not a relaxed URL validator.
    if value.len() > 1024 {
        return Err(error("invalid_dns_owner"));
    }
    let name = value.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<_> = name.split('.').collect();
    let host_start = labels
        .iter()
        .rposition(|label| label.starts_with('_'))
        .ok_or_else(|| error("invalid_dns_owner"))?
        + 1;
    // Preserve the original requirement for a fully qualified host suffix.
    domain_name(&labels[host_start..].join("."))?;
    let mut host_labels = Vec::new();
    for label in &labels {
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
            host_labels.push(*label);
        }
    }
    let canonical_host = domain_name(&host_labels.join("."))?;
    let canonical_labels: Vec<_> = canonical_host.split('.').collect();
    if labels.len() != canonical_labels.len() {
        return Err(error("invalid_dns_owner"));
    }
    let canonical = labels
        .iter()
        .zip(canonical_labels)
        .map(|(original, host)| {
            if original.starts_with('_') {
                *original
            } else {
                host
            }
        })
        .collect::<Vec<_>>()
        .join(".");
    if canonical.len() > 253 {
        return Err(error("invalid_dns_owner"));
    }
    Ok(canonical)
}
