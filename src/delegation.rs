//! Parent delegation evidence from bounded iteration; no credential or local service lookup.
mod referral;
mod walk;
use crate::Result;
pub use walk::details;
pub fn query(input: &str) -> Result<Vec<String>> {
    Ok(details(input)?.nameservers)
}

#[derive(Debug, serde::Serialize)]
pub struct Delegation {
    pub domain: String,
    pub nameservers: Vec<String>,
    pub parent_server: Ipv4Addr,
    pub child_addresses: Vec<Ipv4Addr>,
}

#[cfg(test)]
mod tests;
