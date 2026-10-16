//! Read-only planner example; never applies a plan or prints the full DNS inventory.
use zixcel_domain::{
    Error, Result,
    record_editor::{Edit, Editor, RecordData, RecordType, Scope},
    transport::{HttpTransport, Provider},
};
fn value(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| Error::new("example_scope_missing"))
}
fn main() -> Result<()> {
    let domain = value("DNS_ZONE_DOMAIN")?;
    let scope = Scope {
        account: value("CLOUDFLARE_ACCOUNT_ID")?,
        zone: value("CLOUDFLARE_ZONE_ID")?,
        domain: domain.clone(),
    };
    let mut editor = Editor::new(scope)?;
    let mut transport = HttpTransport::from_env(Provider::Cloudflare, "CLOUDFLARE_API_TOKEN")?;
    let review = editor.plan(
        Edit::Create {
            record: RecordData {
                kind: RecordType::TXT,
                name: format!("_verification.{domain}"),
                content: "synthetic-planning-example".into(),
                ttl: 3600,
                proxied: false,
                priority: None,
            },
        },
        &mut transport,
    )?;
    println!(
        "{}",
        serde_json::json!({"scope":review.plan.scope,"edit":review.plan.edit,
        "expires_at":review.plan.expires_at,"sha256":review.sha256,"writes_performed":false})
    );
    // A host approval UI must retain this Editor and independently approve the
    // reviewed hash before calling apply. This example intentionally never does.
    Ok(())
}
