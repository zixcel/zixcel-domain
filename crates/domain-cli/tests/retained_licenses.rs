use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
#[test]
fn omitted_crate_licenses_match_the_recorded_official_source_bytes() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/native-release/notices");
    for package in ["jni-0.22.4", "jni-macros-0.22.4", "jni-sys-macros-0.4.1"] {
        let root = base.join(package);
        let record: Value =
            serde_json::from_slice(&fs::read(root.join("NOTICE.source.json")).unwrap()).unwrap();
        assert_eq!(
            format!(
                "{}-{}",
                record["package"].as_str().unwrap(),
                record["version"].as_str().unwrap()
            ),
            package
        );
        assert_eq!(record["declared_license"], "MIT OR Apache-2.0");
        let commit = record["source_commit"].as_str().unwrap();
        assert_eq!(commit.len(), 40);
        assert!(commit.bytes().all(|b| b.is_ascii_hexdigit()));
        let files = record["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        for file in files {
            let name = file["file"].as_str().unwrap();
            assert!(["LICENSE-MIT", "LICENSE-APACHE"].contains(&name));
            let url = file["url"].as_str().unwrap();
            assert!(url.starts_with("https://raw.githubusercontent.com/jni-rs/"));
            assert!(url.ends_with(&format!("/{commit}/{name}")));
            let bytes = fs::read(root.join(name)).unwrap();
            let actual: String = Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(actual, file["sha256"].as_str().unwrap());
        }
    }
}
