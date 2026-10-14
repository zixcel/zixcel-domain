#![cfg(unix)]
use serde_json::Value;
use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Cleanup {
    child: Child,
    root: PathBuf,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[test]
fn local_session_limits_socket_access_rejects_unissued_writes_and_never_echoes_credentials() {
    let root = std::env::temp_dir().join(format!("zixcel-session-test-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("control.sock");
    let secret = "fixture-credential-do-not-log";
    let child = Command::new(env!("CARGO_BIN_EXE_zixcel-domain"))
        .args([
            "domain-session",
            socket.to_str().unwrap(),
            "example.test",
            "00000000000000000000000000000001",
        ])
        .env("VALUEDOMAIN_ACCESS_TOKEN", secret)
        .env("CLOUDFLARE_API_TOKEN", secret)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut guard = Cleanup { child, root };
    let until = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = Command::new(env!("CARGO_BIN_EXE_zixcel-domain"))
        .args(["domain-control", socket.to_str().unwrap(), "status"])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let d: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(d["result"]["domain"], "example.test");
    let output = Command::new(env!("CARGO_BIN_EXE_zixcel-domain"))
        .args([
            "domain-control",
            socket.to_str().unwrap(),
            "apply",
            &"f".repeat(64),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let d: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(d["result"]["error"]["code"], "unissued_or_consumed_plan");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .write_all(format!("{{\"action\":\"status\",\"token\":\"{secret}\"}}").as_bytes())
        .unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).unwrap();
    assert!(!text.contains(secret));
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["error"]["code"],
        "invalid_session_request"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_zixcel-domain"))
        .args(["domain-control", socket.to_str().unwrap(), "stop"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(guard.child.wait().unwrap().success());
    assert!(!socket.exists());
}
#[test]
fn session_refuses_a_non_private_socket_directory() {
    let root =
        std::env::temp_dir().join(format!("zixcel-session-public-test-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zixcel-domain"))
        .args([
            "domain-session",
            root.join("control.sock").to_str().unwrap(),
            "example.test",
            "00000000000000000000000000000001",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["error"]["code"],
        "private_socket_directory_required"
    );
    std::fs::remove_dir(root).unwrap();
}
