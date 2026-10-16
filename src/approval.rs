use crate::{Result, error};
use std::{
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| error("invalid_clock"))
}
pub(crate) fn nonce() -> Result<String> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| error("nonce_failed"))?;
    Ok(bytes.iter().map(|v| format!("{v:02x}")).collect())
}
