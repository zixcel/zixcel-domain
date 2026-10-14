//! A local Unix socket transports intents/results, never provider credentials.
use crate::{
    Result,
    domain_release::Session,
    error,
    transport::{HttpTransport, Provider},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Plan { phase: String },
    Apply { sha256: String },
    Observe {},
    Status {},
    Stop {},
}
fn handle(session: &mut Session, request: Request) -> Result<Value> {
    let mut registrar = HttpTransport::from_env(Provider::ValueDomain, "VALUEDOMAIN_ACCESS_TOKEN")?;
    let mut dns = HttpTransport::from_env(Provider::Cloudflare, "CLOUDFLARE_API_TOKEN")?;
    let mut public = HttpTransport::public_dns()?;
    match request {
        Request::Observe {} => session.observe(&mut registrar, &mut dns, &mut public),
        Request::Plan { phase } => session.plan(&phase, &mut registrar, &mut dns, &mut public),
        Request::Apply { sha256 } => session.apply(&sha256, &mut registrar, &mut dns, &mut public),
        _ => Err(error("invalid_session_request")),
    }
}
struct SocketGuard<'a> {
    path: &'a Path,
    inode: u64,
}
impl Drop for SocketGuard<'_> {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(self.path).is_ok_and(|m| m.ino() == self.inode) {
            let _ = std::fs::remove_file(self.path);
        }
    }
}
pub fn serve(path: &str, domain: &str, account: &str) -> Result<Value> {
    serve_with_policy(path, domain, account, false)
}
pub fn serve_with_policy(
    path: &str,
    domain: &str,
    account: &str,
    allow_empty: bool,
) -> Result<Value> {
    serve_with_policies(path, domain, account, allow_empty, false)
}
pub fn serve_with_policies(
    path: &str,
    domain: &str,
    account: &str,
    allow_empty: bool,
    retire_mail: bool,
) -> Result<Value> {
    let path = Path::new(path);
    let parent = path.parent().ok_or_else(|| error("invalid_socket_path"))?;
    let meta = std::fs::symlink_metadata(parent)
        .map_err(|_| error("private_socket_directory_required"))?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(error("private_socket_directory_required"));
    }
    let mut session = Session::new(domain, account)?;
    if allow_empty {
        session = session.allow_empty_registered_unserved();
    }
    if retire_mail {
        session = session.retire_unused_mail();
    }
    let listener = UnixListener::bind(path).map_err(|_| error("socket_bind_failed"))?;
    let inode = std::fs::symlink_metadata(path)
        .map_err(|_| error("socket_setup_failed"))?
        .ino();
    let _guard = SocketGuard { path, inode };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| error("socket_setup_failed"))?;
    listener
        .set_nonblocking(true)
        .map_err(|_| error("socket_setup_failed"))?;
    let deadline = Instant::now() + Duration::from_secs(1200);
    eprintln!("Local domain session ready; expires in 20 minutes. Keep this terminal open.");
    for _ in 0..100 {
        let (mut stream, _) = loop {
            if Instant::now() >= deadline {
                return Ok(json!({"session_closed":"expired"}));
            }
            match listener.accept() {
                Ok(v) => break v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(200))
                }
                Err(_) => return Err(error("socket_failed")),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| error("socket_failed"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| error("socket_failed"))?;
        let mut bytes = Vec::new();
        let response = if (&mut stream).take(4097).read_to_end(&mut bytes).is_err()
            || bytes.len() > 4096
        {
            json!({"schema_version":1,"error":{"code":"session_request_budget"}})
        } else {
            match serde_json::from_slice::<Request>(&bytes) {
                Ok(Request::Stop {}) => {
                    let _ = stream.write_all(
                        b"{\"schema_version\":1,\"result\":{\"session_closed\":\"requested\"}}",
                    );
                    return Ok(json!({"session_closed":"requested"}));
                }
                Ok(Request::Status {}) => {
                    json!({"schema_version":1,"result":{"ready":true,"domain":domain,"account":account,"remaining_seconds":deadline.saturating_duration_since(Instant::now()).as_secs()}})
                }
                Ok(request) => match handle(&mut session, request) {
                    Ok(value) => json!({"schema_version":1,"result":value}),
                    Err(e) => json!({"schema_version":1,"error":e}),
                },
                Err(_) => json!({"schema_version":1,"error":{"code":"invalid_session_request"}}),
            }
        };
        let bytes = serde_json::to_vec(&response).map_err(|_| error("session_response_failed"))?;
        if bytes.len() <= 1024 * 1024 {
            let _ = stream.write_all(&bytes);
        } else {
            let _ = stream.write_all(
                b"{\"schema_version\":1,\"error\":{\"code\":\"session_response_budget\"}}",
            );
        }
    }
    Ok(json!({"session_closed":"request_budget"}))
}
pub fn control(path: &str, action: &str, argument: Option<&str>) -> Result<Value> {
    let request = match (action, argument) {
        ("plan", Some(phase @ ("prepare_zone" | "change_nameservers"))) => {
            json!({"action":"plan","phase":phase})
        }
        ("apply", Some(hash))
            if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            json!({"action":"apply","sha256":hash})
        }
        ("observe" | "status" | "stop", None) => json!({"action":action}),
        _ => return Err(error("invalid_session_request")),
    };
    let mut stream = UnixStream::connect(path).map_err(|_| error("domain_session_not_running"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .map_err(|_| error("socket_failed"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| error("socket_failed"))?;
    stream
        .write_all(&serde_json::to_vec(&request).map_err(|_| error("invalid_session_request"))?)
        .map_err(|_| error("socket_failed"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|_| error("socket_failed"))?;
    let mut bytes = Vec::new();
    stream
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error("session_response_failed"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(error("session_response_budget"));
    }
    let response: Value =
        serde_json::from_slice(&bytes).map_err(|_| error("invalid_session_response"))?;
    if let Some(e) = response.get("error") {
        return Ok(json!({"status":"rejected","error":e}));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| error("invalid_session_response"))
}
