//! Minimal file log for the service: %ProgramData%\BearWatch\agent.log, capped at 1 MB with
//! one rotated copy. Interactive commands print to the console instead.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config;

const MAX: u64 = 1024 * 1024;

pub fn log(msg: &str) {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let line = format!("{secs} {msg}\n");
    if std::env::var_os("BW_AGENT_CONSOLE").is_some() {
        eprint!("{line}");
        return;
    }
    let dir = config::default_dir();
    let path = dir.join("agent.log");
    if fs::metadata(&path).map(|m| m.len() > MAX).unwrap_or(false) {
        let _ = fs::rename(&path, dir.join("agent.log.1"));
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}
