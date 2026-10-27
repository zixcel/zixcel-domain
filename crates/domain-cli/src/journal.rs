//! Durable per-profile admission. A crash leaves the domain locked for explicit reconciliation.
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zix_native_provider::Error;
pub struct Journal {
    root: PathBuf,
}
pub struct Admission {
    root: PathBuf,
    lock: PathBuf,
    marker: PathBuf,
}
pub fn private(path: &Path, directory: bool) -> Result<(), Error> {
    zix_cli::files::parents(path)?;
    let m = fs::symlink_metadata(path).map_err(|_| Error("private_path_unavailable"))?;
    let owner = fs::metadata("/proc/self")
        .map_err(|_| Error("owner_unavailable"))?
        .uid();
    if !path.is_absolute()
        || fs::canonicalize(path).map_err(|_| Error("private_path_unavailable"))? != path
        || m.uid() != owner
        || m.mode() & 0o077 != 0
        || (if directory { !m.is_dir() } else { !m.is_file() })
    {
        return Err(Error("unsafe_private_path"));
    }
    Ok(())
}
fn create(path: &Path) -> Result<File, Error> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| Error("journal_exists_or_unavailable"))
}
fn sync(root: &Path) -> Result<(), Error> {
    File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error("journal_sync_failed"))
}
impl Journal {
    pub fn pending(&self, hash: &str, domain: &str) -> Result<(), Error> {
        if !zix_operation_contracts::valid_digest(hash)
            || zixcel_domain::domain_name(domain).map_err(|_| Error("invalid_domain"))? != domain
        {
            return Err(Error("invalid_resolution_scope"));
        }
        let read = |name: String| -> Result<String, Error> {
            let path = self.root.join(name);
            private(&path, false)?;
            let bytes = zix_cli::files::read(&path, 128 * 1024, false)?;
            String::from_utf8(bytes).map_err(|_| Error("invalid_journal"))
        };
        if read(format!("{domain}.active"))? != hash
            || read(format!("{hash}.attempt"))? != "admitted; reconcile before replay\n"
        {
            return Err(Error("resolution_journal_mismatch"));
        }
        let receipt: serde_json::Value = serde_json::from_str(&read(format!("{hash}.receipt"))?)
            .map_err(|_| Error("invalid_original_receipt"))?;
        if receipt["status"] != "outcome_unknown"
            || receipt["writes_attempted"] != 1
            || !matches!(
                receipt["error"]["code"].as_str(),
                Some(
                    "dns_readback_mismatch"
                        | "incomplete_inventory"
                        | "inconsistent_inventory"
                        | "readback_drift"
                        | "readback_mismatch"
                )
            )
        {
            return Err(Error("unsupported_original_outcome"));
        }
        Ok(())
    }
    pub fn resolve(
        &self,
        hash: &str,
        domain: &str,
        receipt: &serde_json::Value,
    ) -> Result<(), Error> {
        self.pending(hash, domain)?;
        let resolution = self.root.join(format!("{hash}.resolution"));
        let bytes = serde_json::to_vec(receipt).map_err(|_| Error("encoding_failed"))?;
        if resolution.exists() {
            private(&resolution, false)?;
            if zix_cli::files::read(&resolution, 128 * 1024, false)? != bytes {
                return Err(Error("resolution_already_recorded"));
            }
        } else {
            let mut file = create(&resolution)?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| Error("resolution_write_failed"))?;
        }
        sync(&self.root)?;
        // Archive the lock before releasing it. Original attempt and unknown receipt remain immutable.
        let lock = self.root.join(format!("{domain}.active"));
        let archive = self.root.join(format!("{hash}.resolved-lock"));
        if archive.exists() {
            private(&archive, false)?;
            if zix_cli::files::read(&archive, 128, false)? != hash.as_bytes() {
                return Err(Error("resolution_archive_mismatch"));
            }
        } else {
            fs::hard_link(&lock, archive).map_err(|_| Error("resolution_archive_failed"))?;
        }
        sync(&self.root)?;
        self.pending(hash, domain)?;
        fs::remove_file(lock).map_err(|_| Error("resolution_unlock_failed"))?;
        sync(&self.root)
    }
    pub fn open(root: &Path) -> Result<Self, Error> {
        private(root, true)?;
        Ok(Self { root: root.into() })
    }
    pub fn admit(&self, hash: &str, domain: &str) -> Result<Admission, Error> {
        if !zix_operation_contracts::valid_digest(hash) {
            return Err(Error("invalid_approval_hash"));
        }
        let domain = zixcel_domain::domain_name(domain).map_err(|_| Error("invalid_domain"))?;
        let marker = self.root.join(format!("{hash}.attempt"));
        let mut f = create(&marker)?;
        f.write_all(b"admitted; reconcile before replay\n")
            .and_then(|_| f.sync_all())
            .map_err(|_| Error("journal_write_failed"))?;
        sync(&self.root)?;
        let lock = self.root.join(format!("{domain}.active"));
        let mut f = create(&lock).map_err(|_| Error("domain_locked_reconciliation_required"))?;
        f.write_all(hash.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|_| Error("journal_write_failed"))?;
        sync(&self.root)?;
        Ok(Admission {
            root: self.root.clone(),
            lock,
            marker,
        })
    }
}
impl Admission {
    pub fn finish(self, status: &str, release: bool) -> Result<(), Error> {
        let receipt = self.marker.with_extension("receipt");
        let mut f = create(&receipt)?;
        f.write_all(status.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|_| Error("journal_write_failed"))?;
        sync(&self.root)?;
        if release {
            fs::remove_file(self.lock).map_err(|_| Error("journal_unlock_failed"))?;
            sync(&self.root)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn resolution_preserves_unknown_evidence_and_resumes_interrupted_archival() {
        for interrupted in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "domain-resolution-{}-{interrupted}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let j = Journal::open(&root).unwrap();
            let hash = "a".repeat(64);
            let a = j.admit(&hash, "example.test").unwrap();
            a.finish(r#"{"status":"outcome_unknown","writes_attempted":1,"error":{"code":"dns_readback_mismatch"}}"#,false).unwrap();
            let marker = fs::read(root.join(format!("{hash}.attempt"))).unwrap();
            let original_receipt = fs::read(root.join(format!("{hash}.receipt"))).unwrap();
            let receipt = serde_json::json!({"original_outcome":"unknown","remote_write_attempted":false,"original_replay_allowed":false});
            if interrupted {
                let mut f = create(&root.join(format!("{hash}.resolution"))).unwrap();
                f.write_all(&serde_json::to_vec(&receipt).unwrap()).unwrap();
                f.sync_all().unwrap();
                fs::hard_link(
                    root.join("example.test.active"),
                    root.join(format!("{hash}.resolved-lock")),
                )
                .unwrap();
                assert!(
                    j.resolve(
                        &hash,
                        "example.test",
                        &serde_json::json!({"different":true})
                    )
                    .is_err()
                );
                assert!(root.join("example.test.active").exists());
            }
            assert!(j.pending(&hash, "other.test").is_err());
            j.resolve(&hash, "example.test", &receipt).unwrap();
            assert!(!root.join("example.test.active").exists());
            assert_eq!(
                fs::read(root.join(format!("{hash}.attempt"))).unwrap(),
                marker
            );
            assert_eq!(
                fs::read(root.join(format!("{hash}.receipt"))).unwrap(),
                original_receipt
            );
            assert_eq!(
                fs::read_to_string(root.join(format!("{hash}.resolved-lock"))).unwrap(),
                hash
            );
            assert!(j.admit(&hash, "example.test").is_err());
            j.admit(&"b".repeat(64), "example.test")
                .unwrap()
                .finish("provider_verified", true)
                .unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn permanent_markers_domain_lock_and_unknown_outcome_survive_reopen() {
        let root = std::env::temp_dir().join(format!("domain-journal-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let j = Journal::open(&root).unwrap();
        let a = j.admit(&"a".repeat(64), "example.test").unwrap();
        assert!(
            Journal::open(&root)
                .unwrap()
                .admit(&"a".repeat(64), "example.test")
                .is_err()
        );
        assert!(j.admit(&"b".repeat(64), "example.test").is_err());
        a.finish("outcome_unknown", false).unwrap();
        assert!(j.admit(&"c".repeat(64), "example.test").is_err());
        let a = j.admit(&"d".repeat(64), "other.test").unwrap();
        a.finish("provider_verified", true).unwrap();
        assert!(j.admit(&"d".repeat(64), "other.test").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
