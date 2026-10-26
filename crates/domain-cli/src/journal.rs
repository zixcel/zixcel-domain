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
