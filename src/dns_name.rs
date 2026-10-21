//! DNS service labels are not hostnames or registrar ownership identifiers.
use crate::{Result, domain_name, error};
pub fn record_name(value: &str) -> Result<String> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if value.len() > 253 {
        return Err(error("invalid_dns_owner"));
    }
    let labels: Vec<_> = value.split('.').collect();
    let prefix = labels
        .iter()
        .take_while(|label| label.starts_with('_'))
        .count();
    if prefix == 0 {
        return domain_name(&value);
    }
    for label in &labels[..prefix] {
        if label.len() < 2
            || label.len() > 63
            || label.ends_with('-')
            || !label[1..]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(error("invalid_dns_owner"));
        }
    }
    let suffix = domain_name(&labels[prefix..].join("."))?;
    Ok(format!("{}.{}", labels[..prefix].join("."), suffix))
}
