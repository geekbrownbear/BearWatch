//! HTTPS client for the agent endpoints. Blocking on purpose; only the sensor scan thread uses
//! it besides the service loop.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Deserialize;
use serde_json::json;

use crate::inventory::Inventory;
use crate::sensor::Payload;
use crate::{Result, VERSION};

#[derive(Deserialize, Debug)]
pub struct Plan {
    pub upload: bool,
    pub collect_now: bool,
    pub wua_due: bool,
    pub heartbeat_seconds: u64,
    pub collect_seconds: u64,
    /// Hash of the posture read list. Servers before posture support leave it out.
    #[serde(default)]
    pub posture_hash: Option<String>,
    /// Present only when this PC is its site's sensor. Servers before sensor support leave it out.
    #[serde(default)]
    pub sensor: Option<SensorPlan>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct SensorPlan {
    pub interval_minutes: u64,
}

#[derive(Deserialize)]
struct SensorAck {
    hosts: u64,
}

#[derive(Deserialize)]
pub struct PostureReads {
    pub hash: String,
    pub reads: Vec<String>,
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

/// The server answered 409 to a sensor upload: this PC is no longer the site's sensor.
#[derive(Debug)]
pub struct NotSensor;

impl std::fmt::Display for NotSensor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server says this PC is no longer the site's sensor")
    }
}
impl std::error::Error for NotSensor {}

#[derive(Clone)]
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

    /// The settings values the posture rules need. Fetched only when the heartbeat's hash changes.
    pub fn posture(&self, token: &str) -> Result<PostureReads> {
        Ok(Self::check(self.post("/api/agent/posture", Some(token)).send_json(json!({})))?.into_json()?)
    }

    /// Gzipped JSON; a typical PC inventory is a few KB on the wire.
    pub fn upload(&self, token: &str, inv: &Inventory) -> Result<usize> {
        let body = gzip(&serde_json::to_vec(inv)?)?;
        let req = self.post("/api/agent/inventory", Some(token)).set("Content-Type", "application/json").set("Content-Encoding", "gzip");
        Self::check(req.send_bytes(&body))?;
        Ok(body.len())
    }

    /// A sensor scan, gzipped like the inventory. Returns the host count the server stored.
    pub fn sensor(&self, token: &str, payload: &Payload) -> Result<u64> {
        let body = gzip(&serde_json::to_vec(payload)?)?;
        let req = self.post("/api/agent/sensor", Some(token)).set("Content-Type", "application/json").set("Content-Encoding", "gzip");
        match req.send_bytes(&body) {
            Err(ureq::Error::Status(409, _)) => Err(Box::new(NotSensor)),
            r => Ok(Self::check(r)?.into_json::<SensorAck>()?.hosts),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Api, NotSensor, Plan, SensorPlan};
    use std::io::{BufRead, BufReader, Read, Write};

    /// A one-request HTTP server on loopback. Returns the request head, the gunzipped body and
    /// the result of the sensor upload.
    fn upload_to(status: &str, reply: &'static str) -> (String, serde_json::Value, crate::Result<u64>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let status = status.to_string();
        let server = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let len: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap();
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            let mut s = s;
            write!(s, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}", reply.len()).unwrap();
            let mut json = String::new();
            flate2::read::GzDecoder::new(body.as_slice()).read_to_string(&mut json).unwrap();
            (head, serde_json::from_str(&json).unwrap())
        });
        let api = Api::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let payload = crate::sensor::Payload { agent_version: "0.3.0", started_at: "2026-11-05T09:00:00Z".into(), duration_ms: 5, networks: vec![], hosts: vec![] };
        let result = api.sensor("tok", &payload);
        let (head, body) = server.join().unwrap();
        (head, body, result)
    }

    #[test]
    fn sensor_upload_is_gzipped_json_with_the_token() {
        let (head, body, result) = upload_to("200 OK", r#"{"hosts": 7}"#);
        assert_eq!(result.unwrap(), 7);
        assert!(head.starts_with("POST /api/agent/sensor HTTP/1.1"));
        let h = head.to_ascii_lowercase();
        assert!(h.contains("authorization: bearer tok\r\n"));
        assert!(h.contains("content-encoding: gzip\r\n"));
        assert!(h.contains("content-type: application/json\r\n"));
        assert_eq!(body["agent_version"], "0.3.0");
        assert_eq!(body["hosts"], serde_json::json!([]));
    }

    #[test]
    fn sensor_upload_409_means_not_the_sensor() {
        let (_, _, result) = upload_to("409 Conflict", r#"{"error": "not the sensor"}"#);
        assert!(result.unwrap_err().is::<NotSensor>());
        let (_, _, result) = upload_to("500 Internal Server Error", "{}");
        assert!(!result.unwrap_err().is::<NotSensor>());
    }

    #[test]
    fn plan_with_and_without_sensor() {
        let old = r#"{"upload":false,"collect_now":false,"wua_due":false,"heartbeat_seconds":900,"collect_seconds":14400,"posture_hash":"abc"}"#;
        let p: Plan = serde_json::from_str(old).unwrap();
        assert_eq!(p.sensor, None);
        let new = r#"{"upload":false,"collect_now":false,"wua_due":false,"heartbeat_seconds":900,"collect_seconds":14400,"sensor":{"interval_minutes":360}}"#;
        let p: Plan = serde_json::from_str(new).unwrap();
        assert_eq!(p.sensor, Some(SensorPlan { interval_minutes: 360 }));
        assert_eq!(p.posture_hash, None);
        let null: Plan = serde_json::from_str(&new.replace(r#"{"interval_minutes":360}"#, "null")).unwrap();
        assert_eq!(null.sensor, None);
    }
}
