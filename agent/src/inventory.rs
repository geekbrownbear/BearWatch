//! What is installed, read straight from the registry.
//!
//! No WMI, no PowerShell, no file system walk: a few thousand registry reads, well under a
//! second. Sources:
//! - Windows version, build and revision (UBR): HKLM\...\Windows NT\CurrentVersion
//! - Installed KBs: Component Based Servicing packages in state Installed or Permanent
//! - Programs: the Uninstall keys (64-bit, 32-bit, and each loaded user hive)
//! - Settings for the server's posture rules: see posture.rs

use std::collections::BTreeSet;

use serde::Serialize;
use sha2::{Digest, Sha256};
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
use winreg::RegKey;

use crate::posture::{self, Posture};
use crate::wua::WuaResult;
use crate::{Result, VERSION};

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
/// HKCU\Software is shared between the 32-bit and 64-bit views, so KEY_WOW64_32KEY changes
/// nothing there. Some 32-bit installers still write this literal path in the user hive.
const UNINSTALL_USER_WOW: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
const CBS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing";
const CBS_INSTALL_PENDING: u32 = 0x60;
const CBS_INSTALLED: u32 = 0x70;
const CBS_PERMANENT: u32 = 0x80;

#[derive(Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Program {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    pub scope: &'static str,
}

#[derive(Serialize, Clone)]
pub struct OsInfo {
    pub caption: String,
    pub build: String,
    pub arch: &'static str,
    pub server: bool,
    pub server_core: bool,
    pub reboot_pending: bool,
}

#[derive(Serialize, Clone)]
pub struct Inventory {
    pub hash: String,
    pub agent_version: &'static str,
    pub hostname: String,
    pub os: OsInfo,
    pub kbs: Vec<String>,
    /// Installed but waiting for a restart (CBS "install pending").
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pending_kbs: Vec<String>,
    pub software: Vec<Program>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wua: Option<WuaResult>,
    /// Only once the server has sent a read list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<Posture>,
}

pub struct Identity {
    pub hostname: String,
    pub machine_guid: String,
}

fn hklm(path: &str) -> Option<RegKey> {
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY).ok()
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
}

pub fn identity() -> Result<Identity> {
    let key = hklm(r"SOFTWARE\Microsoft\Cryptography").ok_or("cannot open the Cryptography key")?;
    let machine_guid: String = key.get_value("MachineGuid")?;
    Ok(Identity { hostname: hostname(), machine_guid })
}

pub fn os_info() -> Result<OsInfo> {
    let cv = hklm(CURRENT_VERSION).ok_or("cannot open CurrentVersion")?;
    let major: u32 = cv.get_value("CurrentMajorVersionNumber").unwrap_or(10);
    let minor: u32 = cv.get_value("CurrentMinorVersionNumber").unwrap_or(0);
    let build: String = cv.get_value("CurrentBuild").or_else(|_| cv.get_value("CurrentBuildNumber"))?;
    let ubr: u32 = cv.get_value("UBR").unwrap_or(0);
    let product: String = cv.get_value("ProductName").unwrap_or_default();
    let display: String = cv.get_value("DisplayVersion").or_else(|_| cv.get_value("ReleaseId")).unwrap_or_default();
    let install_type: String = cv.get_value("InstallationType").unwrap_or_else(|_| "Client".into());
    let server = install_type.starts_with("Server");
    // ProductName still says "Windows 10" on Windows 11; the build number tells them apart.
    let build_no: u32 = build.parse().unwrap_or(0);
    let product = if !server && build_no >= 22000 { product.replacen("Windows 10", "Windows 11", 1) } else { product };
    let arch = hklm(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
        .and_then(|k| k.get_value::<String, _>("PROCESSOR_ARCHITECTURE").ok())
        .map(|a| match a.to_ascii_uppercase().as_str() {
            "ARM64" => "arm64",
            "X86" => "x86",
            _ => "x64",
        })
        .unwrap_or("x64");
    let reboot_pending = hklm(&format!(r"{CBS}\RebootPending")).is_some()
        || hklm(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired").is_some();
    Ok(OsInfo {
        caption: format!("{product} {display}").trim().to_string(),
        build: format!("{major}.{minor}.{build}.{ubr}"),
        arch,
        server,
        server_core: install_type == "Server Core",
        reboot_pending,
    })
}

/// "KB" followed by 6 to 8 digits, anywhere in s.
fn find_kb(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i + 2 < b.len() {
        if (b[i] == b'K' || b[i] == b'k') && (b[i + 1] == b'B' || b[i + 1] == b'b') {
            let digits = b[i + 2..].iter().take_while(|c| c.is_ascii_digit()).count();
            if (6..=8).contains(&digits) {
                return Some(format!("KB{}", &s[i + 2..i + 2 + digits]));
            }
        }
        i += 1;
    }
    None
}

/// (KBs whose servicing package is fully installed, KBs installed but waiting for a restart).
/// A pending package does not count as installed yet, which is also why the server trusts the
/// running build over the first list. The second lets it say which fix needs only a restart.
pub fn kbs() -> (Vec<String>, Vec<String>) {
    let (mut out, mut pending) = (BTreeSet::new(), BTreeSet::new());
    let Some(packages) = hklm(&format!(r"{CBS}\Packages")) else { return (vec![], vec![]) };
    for name in packages.enum_keys().flatten() {
        if !name.starts_with("Package_for_") {
            continue; // thousands of component packages; only these carry update identities
        }
        let Ok(pkg) = packages.open_subkey_with_flags(&name, KEY_READ) else { continue };
        let state: u32 = pkg.get_value("CurrentState").unwrap_or(0);
        let into = match state {
            CBS_INSTALLED | CBS_PERMANENT => &mut out,
            CBS_INSTALL_PENDING => &mut pending,
            _ => continue,
        };
        let location: String = pkg.get_value("InstallLocation").unwrap_or_default();
        if let Some(kb) = find_kb(&name).or_else(|| find_kb(&location)) {
            into.insert(kb);
        }
    }
    let pending = pending.difference(&out).cloned().collect();
    (out.into_iter().collect(), pending)
}

fn read_uninstall(root: &RegKey, path: &str, flags: u32, scope: &'static str, out: &mut BTreeSet<Program>) {
    let Ok(key) = root.open_subkey_with_flags(path, KEY_READ | flags) else { return };
    for sub in key.enum_keys().flatten() {
        let Ok(app) = key.open_subkey_with_flags(&sub, KEY_READ | flags) else { continue };
        let name: String = match app.get_value("DisplayName") {
            Ok(n) => n,
            Err(_) => continue,
        };
        let name = name.trim().to_string();
        if name.is_empty() {
            continue;
        }
        // Components hidden from Apps & Features, and updates listed under their parent.
        if app.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1 || app.get_value::<String, _>("ParentKeyName").is_ok() {
            continue;
        }
        let release: String = app.get_value("ReleaseType").unwrap_or_default();
        if matches!(release.as_str(), "Update" | "Hotfix" | "Security Update") {
            continue;
        }
        let version: String = app.get_value("DisplayVersion").unwrap_or_default();
        let publisher: Option<String> = app.get_value::<String, _>("Publisher").ok().map(|p| p.trim().to_string()).filter(|p| !p.is_empty());
        out.insert(Program { name: truncate(name, 400), version: truncate(version.trim().to_string(), 120), publisher: publisher.map(|p| truncate(p, 200)), scope });
    }
}

fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

/// Programs for the whole machine and for every user signed in right now. Per-user installs
/// of users who are signed out are not read; loading their registry hives would be intrusive.
pub fn software() -> Vec<Program> {
    let mut out = BTreeSet::new();
    let lm = RegKey::predef(HKEY_LOCAL_MACHINE);
    read_uninstall(&lm, UNINSTALL, KEY_WOW64_64KEY, "machine", &mut out);
    read_uninstall(&lm, UNINSTALL, KEY_WOW64_32KEY, "machine", &mut out);
    let users = RegKey::predef(HKEY_USERS);
    for sid in users.enum_keys().flatten() {
        if sid.starts_with("S-1-5-21-") && !sid.ends_with("_Classes") {
            read_uninstall(&users, &format!(r"{sid}\{UNINSTALL}"), 0, "user", &mut out);
            read_uninstall(&users, &format!(r"{sid}\{UNINSTALL_USER_WOW}"), 0, "user", &mut out);
        }
    }
    // The same program often appears in more than one view; keep one per name and version.
    let mut seen = BTreeSet::new();
    out.into_iter().filter(|p| seen.insert((p.name.to_lowercase(), p.version.clone()))).collect()
}

/// `reads`: the posture read list and its hash, if the server has sent one.
pub fn collect(wua: Option<WuaResult>, reads: Option<(&str, &[String])>) -> Result<Inventory> {
    let (kbs, pending_kbs) = kbs();
    let posture = reads.map(|(hash, list)| posture::collect(hash, list));
    let mut inv = Inventory { hash: String::new(), agent_version: VERSION, hostname: hostname(), os: os_info()?, kbs, pending_kbs, software: software(), wua, posture };
    inv.hash = hash(&inv)?;
    Ok(inv)
}

/// SHA-256 of everything except the hash itself. Lists are sorted, so the same PC state
/// always produces the same hash and an unchanged PC never uploads.
fn hash(inv: &Inventory) -> Result<String> {
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&(&inv.hostname, &inv.os, &inv.kbs, &inv.pending_kbs, &inv.software, &inv.wua, &inv.posture))?);
    Ok(h.finalize().iter().take(16).map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::find_kb;

    #[test]
    fn kb_from_package_names() {
        assert_eq!(find_kb("Package_for_KB5054156~31bf3856ad364e35~amd64~~26100.6717.1.4").as_deref(), Some("KB5054156"));
        assert_eq!(find_kb(r"\\?\C:\WINDOWS\SoftwareDistribution\Download\x\Windows11.0-KB5126052-x64-NDP481.cab").as_deref(), Some("KB5126052"));
        assert_eq!(find_kb("Package_for_ServicingStack_9441~31bf3856ad364e35"), None);
        assert_eq!(find_kb("KB12"), None);
    }
}
