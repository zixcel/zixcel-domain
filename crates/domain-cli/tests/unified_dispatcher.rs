use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
};
struct Context {
    root: std::path::PathBuf,
    profile: std::path::PathBuf,
}
impl Context {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "domain-dispatch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let manifest = root.join("domain.json");
        fs::write(
            &manifest,
            serde_json::to_vec(&zixcel_domain_cli::manifest()).unwrap(),
        )
        .unwrap();
        let profile = root.join("profile.json");
        fs::write(&profile,json!({"domain":"example.test","target":{"provider":"valuedomain","namespace":"registered"},"journal_directory":root}).to_string()).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o600)).unwrap();
        let c = Self { root, profile };
        let out = c.run(&[
            "extensions",
            "add",
            "--manifest",
            manifest.to_str().unwrap(),
            "--manifest-sha256",
            &zix_cli::files::digest(&fs::read(&manifest).unwrap()),
            "--executable",
            env!("CARGO_BIN_EXE_zix-domain"),
            "--executable-sha256",
            &zix_cli::files::digest(&fs::read(env!("CARGO_BIN_EXE_zix-domain")).unwrap()),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        c
    }
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_dispatcher-probe"))
            .env_clear()
            .env("XDG_CONFIG_HOME", &self.root)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn actual_dispatcher_installs_v2_provider_routes_reads_and_refuses_unattended_writes() {
    let c = Context::new();
    let out = c.run(&["describe", "domain", "--format", "json"]);
    assert!(out.status.success());
    let m: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(m["schema"], "zix-extension/v2");
    let out = c.run(&[
        "domain",
        "dns",
        "export",
        "--profile",
        c.profile.to_str().unwrap(),
    ]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"], "credential_missing");
    let out = c.run(&[
        "domain",
        "dns",
        "records",
        "apply",
        "--profile",
        c.profile.to_str().unwrap(),
        "--plan-file",
        "/nonexistent",
        "--approval-sha256",
        &"a".repeat(64),
        "--journal-directory",
        c.root.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("interactive_authorization_required"));
    assert!(!c.root.join("example.test.active").exists());
    let out = c.run(&[
        "domain",
        "dns",
        "inspect",
        "--domain",
        "example.test",
        "--type",
        "INVALID",
    ]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"], "unsupported_dns_query");
}
