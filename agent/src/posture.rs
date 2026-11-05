//! Windows settings values for the server's posture rules (server/bearwatch/posture.py,
//! docs/posture.md).
//!
//! The server sends the list of values to read; the agent reads them, read-only, and only
//! inside ALLOWED_KEYS, whatever the list asks for. It sends back numbers and yes/no, never
//! text: a text value is sent as a number only when it is a plain number, and otherwise as
//! "set". A text value whose name could hold a secret is always sent as "set". So the list
//! cannot be used to pull passwords or other data off the PC, even by someone who controls the
//! server.

use std::collections::BTreeMap;

use serde::Serialize;
use windows::Win32::System::SecurityCenter::{
    WscGetSecurityProviderHealth, WSC_SECURITY_PROVIDER, WSC_SECURITY_PROVIDER_ANTIVIRUS, WSC_SECURITY_PROVIDER_FIREWALL,
    WSC_SECURITY_PROVIDER_HEALTH,
};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ, REG_QWORD, REG_SZ};
use winreg::types::FromRegValue;
use winreg::{RegKey, RegValue};

/// Keep in step with ALLOWED_KEYS in server/bearwatch/posture.py. Settings and policy keys only.
const ALLOWED_KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Policies\",
    r"HKLM\SOFTWARE\Microsoft\Policies\",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\",
    r"HKLM\SOFTWARE\Microsoft\Windows Defender\",
    r"HKLM\SYSTEM\CurrentControlSet\Control\",
    r"HKLM\SYSTEM\CurrentControlSet\Services\",
];
/// Health from Windows Security Center, which covers third-party antivirus and firewalls too.
const WSC_ANTIVIRUS: &str = "wsc:antivirus";
const WSC_FIREWALL: &str = "wsc:firewall";
/// A value whose name contains one of these is only ever reported as "set".
const SECRET_NAMES: &[&str] = &["password", "pwd", "secret", "passphrase", "credential", "token"];
pub const MAX_READS: usize = 300;
const MAX_READ_LEN: usize = 400;

/// One read's result. Serializes to a number, true/false (key exists), "set", or null.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum Value {
    Num(i64),
    Key(bool),
    Set(&'static str),
    Missing,
}

const SET: Value = Value::Set("set");

#[derive(Serialize, Clone, Debug)]
pub struct Posture {
    pub hash: String,
    pub values: BTreeMap<String, Value>,
}

/// A WSC builtin, or an HKLM key (optionally ":value") inside ALLOWED_KEYS.
pub fn allowed(read: &str) -> bool {
    if read == WSC_ANTIVIRUS || read == WSC_FIREWALL {
        return true;
    }
    if read.len() > MAX_READ_LEN || read.contains('*') || read.contains('/') || read.contains(r"\\") {
        return false;
    }
    let key = read.rsplit_once(':').map_or(read, |(k, _)| k);
    let key = format!("{}\\", key.to_ascii_uppercase());
    ALLOWED_KEYS.iter().any(|p| key.starts_with(&p.to_ascii_uppercase()))
}

fn secret(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SECRET_NAMES.iter().any(|s| n.contains(s))
}

/// A plain whole number, as text values like AutoAdminLogon ("1") hold.
fn number_text(s: &str) -> Option<i64> {
    let t = s.trim().trim_end_matches('\0');
    let digits = t.strip_prefix('-').unwrap_or(t);
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

/// DWORDs and QWORDs are on/off switches and levels, and are sent as numbers whatever their
/// name (UseLogonCredential and AdmPwdEnabled are switches, not secrets). Text is where a
/// password could sit, even an all-digit one, so a text value with a secret-looking name is
/// only ever "set".
fn convert(name: &str, raw: &RegValue) -> Value {
    match raw.vtype {
        REG_DWORD if raw.bytes.len() == 4 => Value::Num(i64::from(u32::from_le_bytes(raw.bytes[..4].try_into().unwrap_or_default()))),
        REG_QWORD if raw.bytes.len() == 8 => {
            i64::try_from(u64::from_le_bytes(raw.bytes[..8].try_into().unwrap_or_default())).map_or(SET, Value::Num)
        }
        REG_SZ | REG_EXPAND_SZ if !secret(name) => String::from_reg_value(raw).ok().and_then(|s| number_text(&s)).map_or(SET, Value::Num),
        _ => SET,
    }
}

fn registry(read: &str) -> Value {
    let (key, name) = match read.rsplit_once(':') {
        Some((k, v)) => (k, Some(v)),
        None => (read, None),
    };
    let sub = &key[5..]; // after "HKLM\", which allowed() guarantees
    let opened = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(sub, KEY_READ | KEY_WOW64_64KEY);
    match (opened, name) {
        (Ok(_), None) => Value::Key(true),
        (Err(_), None) => Value::Key(false),
        (Err(_), Some(_)) => Value::Missing,
        (Ok(k), Some(n)) => k.get_raw_value(n).map_or(Value::Missing, |raw| convert(n, &raw)),
    }
}

/// 0 good, 1 not monitored (nothing registered), 2 poor (off or out of date), 3 snoozed.
fn wsc(provider: WSC_SECURITY_PROVIDER) -> Value {
    let mut health = WSC_SECURITY_PROVIDER_HEALTH(0);
    // The provider ids are small positive flags; the API takes them as a u32 bit mask.
    match unsafe { WscGetSecurityProviderHealth(provider.0 as u32, &mut health) } {
        Ok(()) => Value::Num(i64::from(health.0)),
        Err(_) => Value::Missing, // no Security Center (Windows Server)
    }
}

/// Read every allowed value in the list. Reads outside the allowlist are left out, so the
/// server marks the rules that need them as not checked rather than passed.
pub fn collect(hash: &str, reads: &[String]) -> Posture {
    let mut values = BTreeMap::new();
    for r in reads.iter().take(MAX_READS) {
        if !allowed(r) {
            continue;
        }
        let v = match r.as_str() {
            WSC_ANTIVIRUS => wsc(WSC_SECURITY_PROVIDER_ANTIVIRUS),
            WSC_FIREWALL => wsc(WSC_SECURITY_PROVIDER_FIREWALL),
            _ => registry(r),
        };
        values.insert(r.clone(), v);
    }
    Posture { hash: hash.to_string(), values }
}

#[cfg(test)]
mod tests {
    use super::{allowed, convert, number_text, secret, Value, SET};
    use winreg::enums::{REG_BINARY, REG_DWORD, REG_SZ};
    use winreg::RegValue;

    fn text(s: &str) -> RegValue {
        let bytes = s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        RegValue { bytes, vtype: REG_SZ }
    }

    fn dword(n: u32) -> RegValue {
        RegValue { bytes: n.to_le_bytes().to_vec(), vtype: REG_DWORD }
    }

    #[test]
    fn switches_keep_their_numbers_and_secrets_stay_hidden() {
        // Switch names that merely contain "credential" or "pwd" (the WDigest and LAPS rules).
        assert_eq!(convert("UseLogonCredential", &dword(1)), Value::Num(1));
        assert_eq!(convert("AdmPwdEnabled", &dword(0)), Value::Num(0));
        assert_eq!(convert("AutoAdminLogon", &text("1")), Value::Num(1));
        // Text under a secret name is never sent, not even when it is all digits.
        assert_eq!(convert("DefaultPassword", &text("123456")), SET);
        assert_eq!(convert("DefaultPassword", &text("hunter2")), SET);
        assert_eq!(convert("ProductName", &text("Windows 11 Pro")), SET);
        assert_eq!(convert("Blob", &RegValue { bytes: vec![1, 2], vtype: REG_BINARY }), SET);
    }

    #[test]
    fn allowlist() {
        assert!(allowed(r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:NoLMHash"));
        assert!(allowed(r"hklm\system\currentcontrolset\services\srv"));
        assert!(allowed(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:AutoAdminLogon"));
        assert!(allowed("wsc:antivirus"));
        assert!(!allowed(r"HKLM\SAM\SAM\Domains"));
        assert!(!allowed(r"HKLM\SECURITY\Policy\Secrets"));
        assert!(!allowed(r"HKLM\SOFTWARE\RealVNC\vncserver:Password"));
        assert!(!allowed(r"HKCU\Software\Policies\x:y"));
        assert!(!allowed(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion:ProductName"));
        assert!(!allowed(r"HKLM\SOFTWARE\Policies\*:x"));
    }

    #[test]
    fn numbers_and_secrets() {
        assert_eq!(number_text("1"), Some(1));
        assert_eq!(number_text(" 42\0"), Some(42));
        assert_eq!(number_text("2.0"), None);
        assert_eq!(number_text("hunter2"), None);
        assert!(secret("DefaultPassword"));
        assert!(!secret("AutoAdminLogon"));
    }
}
