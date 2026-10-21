//! Provider glue over the existing Domain owner; no second DNS or authorization authority.
mod catalog;
mod registrar;
mod security;
pub use catalog::manifest;
pub use registrar::observe;
pub use security::execute;
