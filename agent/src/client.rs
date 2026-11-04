//! HTTPS client for the three agent endpoints. Blocking and single-threaded on purpose.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Deserialize;
use serde_json::json;

use crate::inventory::Inventory;
use crate::{Result, VERSION};

#[derive(Deserialize, Debug)]
pub struct Plan {
    pub upload: bool,
    pub collect_now: bool,
    pub wua_due: bool,
    pub heartbeat_seconds: u64,
    pub collect_seconds: u64,
}

#[derive(Deserialize)]
pub struct Enrolled {
    pub device_id: i64,
    pub token: String,
}

/// The server said this token is no longer valid (device re-enrolled or removed).
#[derive(Debug)]
pub struct Revoked;

impl std::fmt::Display for Revoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server no longer accepts this device token; run `bw-agent enroll` again")
    }
}
impl std::error::Error for Revoked {}

pub struct Api {
    agent: ureq::Agent,
    base: String,
}

pub fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

fn local(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

impl Api {
    pub fn new(server: &str) -> Result<Self> {
        let base = server.trim().trim_end_matches('/').to_string();
        let host = base.split("://").nth(1).unwrap_or("").split(['/', ':']).next().unwrap_or("");
        if !(base.starts_with("https://") || (base.starts_with("http://") && local(host))) {
            return Err("the server URL must start with https:// (plain http is allowed only for localhost)".into());
        }
        let tls = native_tls::TlsConnector::new()?;
        let agent = ureq::AgentBuilder::new()
            .tls_connector(Arc::new(tls))
            .timeout_connect(Duration::from_secs(15))
            .timeout(Duration::from_secs(60))
            .user_agent(&format!("bw-agent/{VERSION}"))
            .build();
        Ok(Self { agent, base })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn post(&self, path: &str, token: Option<&str>) -> ureq::Request {
        let r = self.agent.post(&format!("{}{path}", self.base));
        match token {
            Some(t) => r.set("Authorization", &format!("Bearer {t}")),
            None => r,
        }
    }

    fn check(r: std::result::Result<ureq::Response, ureq::Error>) -> Result<ureq::Response> {
        match r {
            Ok(resp) => Ok(resp),
            Err(ureq::Error::Status(401, _)) => Err(Box::new(Revoked)),
            Err(ureq::Error::Status(code, resp)) => Err(format!("server returned {code}: {}", resp.into_string().unwrap_or_default().chars().take(300).collect::<String>()).into()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn enroll(&self, key: &str, machine_guid: &str, hostname: &str) -> Result<Enrolled> {
        let body = json!({"enroll_key": key, "machine_guid": machine_guid, "hostname": hostname, "agent_version": VERSION});
        let resp = Self::check(self.post("/api/agent/enroll", None).send_json(body)).map_err(|e| {
            if e.is::<Revoked>() { "the server did not accept that enrollment key".into() } else { e }
        })?;
        Ok(resp.into_json()?)
    }

    pub fn heartbeat(&self, token: &str, inventory_hash: Option<&str>) -> Result<Plan> {
        let body = json!({"agent_version": VERSION, "inventory_hash": inventory_hash});
        Ok(Self::check(self.post("/api/agent/heartbeat", Some(token)).send_json(body))?.into_json()?)
    }

    /// Gzipped JSON; a typical PC inventory is a few KB on the wire.
    pub fn upload(&self, token: &str, inv: &Inventory) -> Result<usize> {
        let body = gzip(&serde_json::to_vec(inv)?)?;
        let req = self.post("/api/agent/inventory", Some(token)).set("Content-Type", "application/json").set("Content-Encoding", "gzip");
        Self::check(req.send_bytes(&body))?;
        Ok(body.len())
    }
}
