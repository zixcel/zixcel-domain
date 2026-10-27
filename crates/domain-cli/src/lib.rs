//! Provider glue over the existing Domain owner; no second DNS or authorization authority.
mod catalog;
mod registrar;
mod security;
pub use catalog::manifest;
pub use registrar::observe;
pub use security::execute;
pub mod reconciliation;

mod journal;
mod operations;

pub fn guidance() -> zix_native_provider::Result<zix_native_provider::GuidanceCatalog> {
    let manifest = manifest();
    zix_native_provider::guidance::catalog(&manifest, include_bytes!("../api/guidance.json"))
}
