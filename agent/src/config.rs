//! Agent state: server URL, device token, last uploaded hash, last Windows Update result, the
//! posture read list the server sent last, and the sensor schedule.
//!
//! Lives in %ProgramData%\BearWatch\agent.json. The folder is locked to SYSTEM and
//! Administrators, because the device token lets anyone holding it report for this PC.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::wua::WuaResult;
use crate::Result;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub server: String,
    pub device_id: i64,
    pub token: String,
    #[serde(default)]
    pub last_upload_hash: Option<String>,
    #[serde(default)]
    pub wua: Option<WuaResult>,
    /// Hash and list of the settings values the server's posture rules read.
    #[serde(default)]
    pub posture_hash: Option<String>,
    #[serde(default)]
    pub posture_reads: Vec<String>,
    /// When the last sensor scan was started (unix seconds), whether or not it succeeded.
    #[serde(default)]
    pub sensor_last_scan: Option<u64>,
    /// The server answered 409 to a sensor upload. No scan until a heartbeat sent after the
    /// 409 names this PC the sensor again (see run::sensor_plan). Kept across a restart, and
    /// cleared by the first heartbeat after it.
    #[serde(default)]
    pub sensor_declined: bool,
}

pub fn default_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("BearWatch")
}

pub fn path(custom: Option<&Path>) -> PathBuf {
    custom.map(Path::to_path_buf).unwrap_or_else(|| default_dir().join("agent.json"))
}

pub fn load(path: &Path) -> Result<Config> {
    let raw = fs::read(path).map_err(|e| format!("cannot read {}: {e}. Run `bw-agent enroll` first.", path.display()))?;
    Ok(serde_json::from_slice(&raw)?)
}

pub fn save(path: &Path, cfg: &Config) -> Result<()> {
    let dir = path.parent().ok_or("config path has no folder")?;
    let fresh = !dir.exists();
    fs::create_dir_all(dir)?;
    if fresh && dir == default_dir() {
        lock_down(dir)?;
    }
    // Write then rename, so a crash or power loss never leaves a half-written token file.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(cfg)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Replace inherited permissions with SYSTEM and Administrators only.
fn lock_down(dir: &Path) -> Result<()> {
    let status = Command::new("icacls")
        .arg(dir)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
        .stdout(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("could not restrict permissions on {} (run as administrator)", dir.display()).into());
    }
    Ok(())
}
