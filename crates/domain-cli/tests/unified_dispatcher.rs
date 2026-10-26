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
#[test]
fn real_terminal_approval_and_profile_binding_stop_before_provider_access() {
    use std::io::Write;
    use zix_operation_contracts::{Binding, LocalPlan};
    let c = Context::new();
    let manifest = serde_json::to_value(zixcel_domain_cli::manifest()).unwrap();
    let binding = Binding::for_catalog(
        "zixcel-domain-cli",
        env!("CARGO_PKG_VERSION"),
        &manifest,
        &zix_cli::files::digest(&fs::read(env!("CARGO_BIN_EXE_zix-domain")).unwrap()),
    );
    let profile: Value = serde_json::from_slice(&fs::read(&c.profile).unwrap()).unwrap();
    let plan = LocalPlan::new(
        "dns.records.apply".into(),
        binding,
        json!({"profile":profile,"profile_sha256":"0".repeat(64),"change":{}}),
    );
    let file = c.root.join("plan.json");
    fs::write(&file, serde_json::to_vec(&plan).unwrap()).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let command = [
        env!("CARGO_BIN_EXE_dispatcher-probe"),
        "domain",
        "dns",
        "records",
        "apply",
        "--profile",
        c.profile.to_str().unwrap(),
        "--plan-file",
        file.to_str().unwrap(),
        "--approval-sha256",
        &plan.digest(),
        "--journal-directory",
        c.root.to_str().unwrap(),
    ]
    .into_iter()
    .map(quote)
    .collect::<Vec<_>>()
    .join(" ");
    for accepted in [false, true] {
        let mut child = Command::new("script")
            .args(["--quiet", "--return", "--command", &command, "/dev/null"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CONFIG_HOME", &c.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            child.stdin.take().unwrap(),
            "{}",
            if accepted {
                plan.digest()
            } else {
                String::new()
            }
        )
        .unwrap();
        let out = child.wait_with_output().unwrap();
        let output = String::from_utf8_lossy(&out.stdout);
        assert!(
            output.contains(if accepted {
                "plan_scope_mismatch"
            } else {
                "approval_declined"
            }),
            "{output}"
        );
        assert!(!c.root.join("example.test.active").exists());
        assert!(!c.root.join(format!("{}.attempt", plan.digest())).exists());
    }
}
