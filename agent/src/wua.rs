//! Windows Update cross-check: ask the Windows Update Agent which updates are missing.
//!
//! This is the one expensive thing the agent can do (the update service may work for a minute
//! or more), so it only runs when the server says the site has it on and it is due (weekly),
//! and only when the PC is on AC power and mostly idle. See system::quiet().

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use windows::core::{Interface, BSTR};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED};
use windows::Win32::System::UpdateAgent::{IStringCollection, IUpdate2, IUpdateSession, UpdateSession};

const TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WuaEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kb: Option<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub is_security: bool,
    pub cves: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WuaResult {
    pub checked_at: String, // RFC 3339, UTC
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub missing: Vec<WuaEntry>,
}

/// Now as RFC 3339 UTC, e.g. 2026-11-05T09:00:00Z. Also used for the sensor payload.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn strings(c: &IStringCollection) -> Vec<String> {
    let n = unsafe { c.Count() }.unwrap_or(0);
    (0..n).filter_map(|i| unsafe { c.get_Item(i) }.ok().map(|s| s.to_string())).collect()
}

fn search_blocking() -> std::result::Result<Vec<WuaEntry>, String> {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).ok().map_err(|e| format!("COM init: {e}"))?;
        let result = (|| -> windows::core::Result<Vec<WuaEntry>> {
            let session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER)?;
            session.SetClientApplicationID(&BSTR::from("BearWatch"))?;
            let searcher = session.CreateUpdateSearcher()?;
            let found = searcher.Search(&BSTR::from("IsInstalled=0 and IsHidden=0 and Type='Software'"))?;
            let updates = found.Updates()?;
            let mut out = Vec::new();
            for i in 0..updates.Count()? {
                let u = updates.get_Item(i)?;
                let title = u.Title()?.to_string();
                let severity = u.MsrcSeverity().map(|s| s.to_string()).ok().filter(|s| !s.is_empty());
                let kb = u.KBArticleIDs().ok().and_then(|c| strings(&c).into_iter().next()).map(|k| format!("KB{}", k.trim_start_matches("KB")));
                // CVE ids live on the newer IUpdate2 interface.
                let cves = u.cast::<IUpdate2>().and_then(|u2| u2.CveIDs()).map(|c| strings(&c)).unwrap_or_default();
                let mut is_security = severity.is_some();
                if let Ok(cats) = u.Categories() {
                    for j in 0..cats.Count().unwrap_or(0) {
                        if let Ok(cat) = cats.get_Item(j) {
                            if cat.Name().map(|n| n == "Security Updates").unwrap_or(false) {
                                is_security = true;
                            }
                        }
                    }
                }
                out.push(WuaEntry { kb, title, severity, is_security, cves });
            }
            Ok(out)
        })();
        CoUninitialize();
        result.map_err(|e| e.message().to_string())
    }
}

/// Run the search in a short-lived child process (`bw-agent wua-scan`). The Windows Update
/// libraries add ~70 MB to whichever process loads them; this way the service itself stays
/// around 10 MB and the memory is returned as soon as the child exits.
pub fn search_isolated() -> WuaResult {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
    let checked_at = now_rfc3339();
    let fail = |e: String| WuaResult { checked_at: checked_at.clone(), error: Some(e), missing: vec![] };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return fail(format!("cannot find own exe: {e}")),
    };
    match std::process::Command::new(exe).arg("wua-scan").creation_flags(CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS).output() {
        Ok(out) if out.status.success() => serde_json::from_slice(&out.stdout).unwrap_or_else(|e| fail(format!("bad wua-scan output: {e}"))),
        Ok(out) => fail(format!("wua-scan exited with {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim())),
        Err(e) => fail(format!("cannot start wua-scan: {e}")),
    }
}

/// Runs the search on its own thread with a 15 minute cap, so a stuck update service can
/// never hang the agent.
pub fn search() -> WuaResult {
    let checked_at = now_rfc3339();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(search_blocking());
    });
    match rx.recv_timeout(TIMEOUT) {
        Ok(Ok(missing)) => WuaResult { checked_at, error: None, missing },
        Ok(Err(e)) => WuaResult { checked_at, error: Some(e), missing: vec![] },
        Err(_) => WuaResult { checked_at, error: Some("Windows Update search timed out after 15 minutes".into()), missing: vec![] },
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc3339_shape() {
        let s = super::now_rfc3339();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z') && &s[4..5] == "-" && &s[10..11] == "T");
    }
}
