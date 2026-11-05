//! Service detection on an open port, plus the configuration checks from checks.rs.
//!
//! Adapted from Proton IP Scanner (https://github.com/geekbrownbear/proton-network-scanner), GPL-3.0-or-later.
//! Proton turns detected software into CPE names for its CVE lookup; the
//! agent leaves CVE matching to the server, so only the name and version are kept here (for the
//! "Software version detected" finding). HTTP goes through ureq 2 with native-tls.
//!
//! | Port(s) | Method |
//! |---|---|
//! | web ports (80, 8080, 443, 8443 ...) | HTTP(S) `GET /`: `Server` / `X-Powered-By` headers, page content |
//! | 22 / anything starting `SSH-` | SSH greeting |
//! | 21 | FTP greeting, then the documented `anonymous` login, then QUIT |
//! | 3306 | MySQL/MariaDB handshake packet (version string) |
//! | 6379 | Redis `INFO server` (read-only; also tells whether a password is required) |
//! | 5900 to 5903 | VNC version and offered security types (no authentication attempted) |
//! | 11211 | memcached `version` |
//! | 1883 | MQTT CONNECT without credentials, then DISCONNECT |
//! | 2375 | Docker Engine API `GET /version` |
//! | 9200 | Elasticsearch `GET /` |
//! | other | read the greeting; if silent, one neutral probe tells Redis / memcached / HTTP / HTTPS apart |
//!
//! Non-destructive by design: only fixed, read-only requests and documented anonymous access.
//! At most 64 KiB is read per response, with timeouts, and all received text is treated as
//! untrusted (cleaned before use). Certificates of scanned devices are not verified (most use
//! self-signed ones); that client is separate from the one that talks to the BearWatch server.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::checks::{self, Finding};
use super::ports::service_name;

/// Most bytes read from one response.
const MAX_READ: usize = 64 * 1024;

/// One piece of software found on a port.
#[derive(Clone, Debug, PartialEq)]
pub struct Product {
    /// e.g. "OpenSSH".
    pub name: String,
    /// As announced, e.g. "9.6p1".
    pub version: String,
}

impl Product {
    /// `update` is e.g. "p1" for OpenSSH, shown right after the version.
    fn new(name: &str, version: &str, update: Option<&str>) -> Product {
        let shown = match update {
            Some(u) if !u.is_empty() => format!("{version}{u}"),
            _ => version.to_string(),
        };
        Product { name: name.into(), version: clean(&shown, 40) }
    }

    pub fn label(&self) -> String {
        if self.version.is_empty() {
            self.name.clone()
        } else {
            format!("{} {}", self.name, self.version)
        }
    }
}

/// What was found on one open port.
#[derive(Clone, Debug)]
pub struct Service {
    pub ip: Ipv4Addr,
    pub port: u16,
    /// Short lowercase service key, e.g. "ssh", "https".
    pub name: &'static str,
    pub products: Vec<Product>,
    /// First line the service sent, or the web server header (cleaned).
    pub banner: Option<String>,
}

/// Shared settings for probing.
pub struct ProbeCtx {
    pub timeout: Duration,
    /// HTTP client for scanned devices: certificates not verified, no proxy, no redirects.
    http: ureq::Agent,
}

impl ProbeCtx {
    pub fn new(timeout: Duration) -> ProbeCtx {
        let mut b = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(timeout * 2)
            .timeout(timeout * 6)
            .user_agent(&format!("Mozilla/5.0 (compatible; BearWatch sensor {})", crate::VERSION));
        // Without a connector https requests simply fail, and the probe moves on.
        if let Ok(tls) = native_tls::TlsConnector::builder().danger_accept_invalid_certs(true).danger_accept_invalid_hostnames(true).build() {
            b = b.tls_connector(Arc::new(tls));
        }
        ProbeCtx { timeout, http: b.build() }
    }
}

const HTTPS_PORTS: [u16; 7] = [443, 4443, 5001, 8443, 9443, 10443, 7443];
const HTTP_PORTS: [u16; 17] = [80, 81, 591, 2375, 3000, 5000, 7547, 8000, 8008, 8080, 8081, 8088, 8090, 8888, 9000, 9200, 32400];

/// Identify the service on ip:port and run the checks that apply to it.
pub fn probe(ip: Ipv4Addr, port: u16, ctx: &ProbeCtx) -> (Service, Vec<Finding>) {
    let mut svc = Service { ip, port, name: service_name(port), products: Vec::new(), banner: None };
    let mut findings = Vec::new();

    match port {
        p if HTTPS_PORTS.contains(&p) => http_probe(&mut svc, &mut findings, ctx, "https"),
        p if HTTP_PORTS.contains(&p) => http_probe(&mut svc, &mut findings, ctx, "http"),
        3306 => mysql_probe(&mut svc, &mut findings, ctx),
        6379 => redis_probe(&mut svc, &mut findings, ctx),
        5900..=5903 => vnc_probe(&mut svc, &mut findings, ctx),
        11211 => memcached_probe(&mut svc, &mut findings, ctx),
        1883 => mqtt_probe(&mut svc, &mut findings, ctx),
        21 => ftp_probe(&mut svc, &mut findings, ctx),
        23 => {
            svc.name = "telnet";
            findings.push(checks::TELNET.finding(port, "Port 23 accepts Telnet connections."));
        }
        3389 => findings.push(checks::RDP_EXPOSED.finding(port, "Port 3389 is open.")),
        445 | 139 => findings.push(checks::SMB_EXPOSED.finding(port, format!("Port {port} is open."))),
        _ => generic_probe(&mut svc, &mut findings, ctx),
    }

    // One informational finding listing the detected software versions.
    let versions: Vec<String> = svc.products.iter().filter(|p| !p.version.is_empty()).map(Product::label).collect();
    if !versions.is_empty() {
        findings.push(checks::VERSION_DISCLOSED.finding(port, versions.join(", ")));
    }
    (svc, findings)
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

/// Unknown port: read a greeting; recognise SSH / FTP / SMTP; else try HTTP.
fn generic_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let banner = connect(svc.ip, svc.port, ctx.timeout).and_then(|mut s| read_line(&mut s, ctx.timeout));
    match banner {
        Some(b) if b.starts_with("SSH-") => {
            svc.name = "ssh";
            svc.products.extend(parse_ssh_banner(&b));
            svc.banner = Some(b);
        }
        Some(b) if b.starts_with("220") => {
            let l = b.to_ascii_lowercase();
            if !l.contains("smtp") && (l.contains("ftp") || parse_ftp_banner(&b).is_some()) {
                // FTP on an unusual port: run the full FTP checks (fresh connection).
                ftp_probe(svc, findings, ctx);
            } else {
                if l.contains("smtp") {
                    svc.name = "smtp";
                }
                svc.products.extend(parse_smtp_banner(&b));
                svc.banner = Some(b);
            }
        }
        Some(b) => svc.banner = Some(b),
        None => {
            // Silent service: one neutral probe tells the common silent protocols apart.
            // "INFO server" is a read-only Redis command; other servers answer with an error.
            let reply = connect(svc.ip, svc.port, ctx.timeout)
                .map(|mut s| {
                    let _ = s.write_all(b"INFO server\r\n");
                    read_some(&mut s, 4096, ctx.timeout)
                })
                .unwrap_or_default();
            let text = String::from_utf8_lossy(&reply);
            if text.contains("redis_version:") || text.starts_with("-NOAUTH") || text.starts_with("-DENIED") {
                redis_probe(svc, findings, ctx);
            } else if text.starts_with("ERROR") {
                memcached_probe(svc, findings, ctx);
            } else if reply.starts_with(&[0x15, 0x03]) {
                // A TLS alert: the service speaks TLS, most likely HTTPS.
                http_probe(svc, findings, ctx, "https");
            } else if text.starts_with("HTTP/") || reply.is_empty() {
                http_probe(svc, findings, ctx, "http");
            }
        }
    }
}

fn http_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx, scheme: &str) {
    let (ip, port) = (svc.ip, svc.port);
    let path = if port == 2375 { "/version" } else { "/" };
    let Some(resp) = http_get(ctx, scheme, ip, port, path) else { return };
    if scheme == "https" {
        svc.name = "https";
    } else if svc.name == "unknown" {
        svc.name = "http";
    }
    if let Some(server) = &resp.server {
        svc.banner = Some(format!("Server: {server}"));
        svc.products.extend(parse_server_header(server));
    }
    if let Some(p) = &resp.powered_by {
        svc.products.extend(parse_server_header(p));
    }

    // Docker Engine API (no TLS, no auth).
    if port == 2375 && resp.body.contains("\"ApiVersion\"") {
        svc.name = "docker";
        if let Some(v) = json_str(&resp.body, &["Version"]) {
            svc.products.push(Product::new("Docker Engine", &v, None));
        }
        findings.push(checks::DOCKER_API.finding(port, "GET /version answered without authentication."));
    }
    // Elasticsearch.
    if resp.body.contains("You Know, for Search") {
        svc.name = "elasticsearch";
        if let Some(v) = json_str(&resp.body, &["version", "number"]) {
            svc.products.push(Product::new("Elasticsearch", &v, None));
        }
        if resp.status == 200 {
            findings.push(checks::ELASTIC_NOAUTH.finding(port, "GET / returned cluster information without credentials."));
        }
    }
    // Password field on a page served without TLS.
    let body = resp.body.to_ascii_lowercase();
    if scheme == "http" && (body.contains("type=\"password\"") || body.contains("type='password'") || body.contains("type=password")) {
        findings.push(checks::HTTP_CLEARTEXT_LOGIN.finding(port, format!("http://{ip}:{port}/ contains a password input field.")));
    }
}

struct HttpResp {
    status: u16,
    server: Option<String>,
    powered_by: Option<String>,
    body: String,
}

fn http_get(ctx: &ProbeCtx, scheme: &str, ip: Ipv4Addr, port: u16, path: &str) -> Option<HttpResp> {
    // The URL is built only from a parsed address, a constant scheme and path, and a number.
    let url = format!("{scheme}://{ip}:{port}{path}");
    let resp = match ctx.http.get(&url).call() {
        Ok(r) => r,
        // 4xx and 5xx still carry the headers and page we want.
        Err(ureq::Error::Status(_, r)) => r,
        Err(_) => return None,
    };
    let server = resp.header("server").map(|s| clean(s, 120));
    let powered_by = resp.header("x-powered-by").map(|s| clean(s, 120));
    let status = resp.status();
    let mut raw = Vec::new();
    let _ = resp.into_reader().take(MAX_READ as u64).read_to_end(&mut raw);
    Some(HttpResp { status, server, powered_by, body: String::from_utf8_lossy(&raw).into_owned() })
}

fn mysql_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    let pkt = read_some(&mut s, 512, ctx.timeout);
    // Packet: 3-byte length, 1-byte sequence, then protocol version 10 and a NUL-terminated
    // server version. 0xFF = error packet (e.g. "host not allowed"), still MySQL/MariaDB.
    match pkt.get(4) {
        Some(10) => {
            let ver: String = pkt.iter().skip(5).take_while(|&&b| b != 0).take(60).map(|&b| b as char).collect();
            svc.name = "mysql";
            svc.banner = Some(clean(&ver, 60));
            svc.products.extend(parse_mysql_version(&ver));
            findings.push(checks::DATABASE_EXPOSED.finding(svc.port, format!("Server version {}", clean(&ver, 60))));
        }
        Some(0xFF) => svc.name = "mysql",
        _ => {}
    }
}

fn redis_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    if s.write_all(b"INFO server\r\n").is_err() {
        return;
    }
    let reply = String::from_utf8_lossy(&read_some(&mut s, 8192, ctx.timeout)).into_owned();
    if reply.contains("redis_version:") {
        svc.name = "redis";
        if let Some(v) = reply.lines().find_map(|l| l.strip_prefix("redis_version:")) {
            svc.products.push(Product::new("Redis", v.trim(), None));
        }
        findings.push(checks::REDIS_NOAUTH.finding(svc.port, "INFO command answered without a password."));
    } else if reply.starts_with("-NOAUTH") || reply.contains("Authentication required") {
        svc.name = "redis";
    }
}

fn vnc_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    let hello = read_some(&mut s, 12, ctx.timeout);
    let Some(ver) = std::str::from_utf8(&hello).ok().filter(|v| v.starts_with("RFB ")) else { return };
    svc.name = "vnc";
    svc.banner = Some(clean(ver, 20));
    let minor: u32 = ver.get(8..11).and_then(|m| m.parse().ok()).unwrap_or(3);
    // Answer with the same protocol version (3.3, 3.7 or 3.8).
    let ours: &[u8] = if minor >= 8 {
        b"RFB 003.008\n"
    } else if minor == 7 {
        b"RFB 003.007\n"
    } else {
        b"RFB 003.003\n"
    };
    if s.write_all(ours).is_err() {
        return;
    }
    let reply = read_some(&mut s, 64, ctx.timeout);
    // 3.3: a 4-byte security type chosen by the server. 3.7+: a count and a list.
    let no_auth = if minor < 7 {
        reply.get(0..4) == Some(&[0, 0, 0, 1])
    } else {
        let n = *reply.first().unwrap_or(&0) as usize;
        reply.iter().skip(1).take(n).any(|&t| t == 1)
    };
    if no_auth {
        findings.push(checks::VNC_NOAUTH.finding(svc.port, "Server offers security type 1 (None)."));
    }
}

fn memcached_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    if s.write_all(b"version\r\n").is_err() {
        return;
    }
    let reply = String::from_utf8_lossy(&read_some(&mut s, 256, ctx.timeout)).into_owned();
    if let Some(v) = reply.strip_prefix("VERSION ") {
        svc.name = "memcached";
        svc.products.push(Product::new("memcached", v.trim(), None));
        findings.push(checks::MEMCACHED_NOAUTH.finding(svc.port, "'version' answered without authentication."));
    }
}

fn mqtt_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    // CONNECT, MQTT 3.1.1, clean session, keep-alive 60 s, client id "bw-sensor", no credentials.
    const CONNECT: [u8; 23] = [0x10, 21, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 60, 0, 9, b'b', b'w', b'-', b's', b'e', b'n', b's', b'o', b'r'];
    if s.write_all(&CONNECT).is_err() {
        return;
    }
    let ack = read_some(&mut s, 4, ctx.timeout);
    if ack.first() == Some(&0x20) {
        svc.name = "mqtt";
        if ack.get(3) == Some(&0) {
            findings.push(checks::MQTT_ANONYMOUS.finding(svc.port, "CONNECT without credentials was accepted (CONNACK 0)."));
        }
        let _ = s.write_all(&[0xE0, 0]); // DISCONNECT
    }
}

fn ftp_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else { return };
    let Some(greeting) = ftp_reply(&mut s, ctx.timeout) else { return };
    if !greeting.starts_with("220") {
        return;
    }
    svc.name = "ftp";
    svc.banner = Some(greeting.clone());
    svc.products.extend(parse_ftp_banner(&greeting));
    findings.push(checks::FTP_CLEARTEXT.finding(svc.port, greeting.clone()));

    // Documented anonymous access only; log out straight away.
    let _ = s.write_all(b"USER anonymous\r\n");
    let mut reply = ftp_reply(&mut s, ctx.timeout).unwrap_or_default();
    if reply.starts_with("331") {
        let _ = s.write_all(b"PASS bearwatch-sensor@example.com\r\n");
        reply = ftp_reply(&mut s, ctx.timeout).unwrap_or_default();
    }
    if reply.starts_with("230") {
        findings.push(checks::FTP_ANONYMOUS.finding(svc.port, format!("Login as 'anonymous' accepted: {reply}")));
    }
    let _ = s.write_all(b"QUIT\r\n");
}

// ---------------------------------------------------------------------------
// Banner parsers (pure functions, unit-tested)
// ---------------------------------------------------------------------------

/// `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` -> OpenSSH 9.6p1.
pub fn parse_ssh_banner(b: &str) -> Option<Product> {
    let software = b.splitn(3, '-').nth(2)?; // "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    let first = software.split_whitespace().next()?;
    if let Some(v) = first.strip_prefix("OpenSSH_") {
        // Windows' built-in server says "OpenSSH_for_Windows_9.5".
        let v = v.strip_prefix("for_Windows_").unwrap_or(v);
        // "9.6p1" -> version 9.6, update p1.
        let (ver, upd) = match v.find('p') {
            Some(i) => (&v[..i], Some(&v[i..])),
            None => (v, None),
        };
        Some(Product::new("OpenSSH", ver, upd))
    } else {
        let v = first.strip_prefix("dropbear_")?;
        Some(Product::new("Dropbear SSH", v, None))
    }
}

/// `Apache/2.4.58 (Ubuntu) OpenSSL/3.0.13` -> [Apache httpd 2.4.58, OpenSSL 3.0.13].
pub fn parse_server_header(h: &str) -> Vec<Product> {
    let mut out = Vec::new();
    for token in h.split_whitespace() {
        // "Name/version" or "Jetty(9.4.53.v20231009)"
        let (name, ver) = match token.split_once('/') {
            Some((n, v)) => (n, v),
            None => match token.split_once('(') {
                Some((n, v)) => (n, v.trim_end_matches(')')),
                None => continue,
            },
        };
        let ver = ver.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        let p = match name.to_ascii_lowercase().as_str() {
            "apache" => Product::new("Apache httpd", ver, None),
            "nginx" => Product::new("nginx", ver, None),
            "lighttpd" => Product::new("lighttpd", ver, None),
            "microsoft-iis" => Product::new("Microsoft IIS", ver, None),
            "openssl" => Product::new("OpenSSL", ver, None),
            "php" => Product::new("PHP", ver.split('-').next().unwrap_or(ver), None),
            "miniserv" => Product::new("Webmin", ver, None),
            "jetty" => Product::new("Jetty", &ver.split('.').take(3).collect::<Vec<_>>().join("."), None),
            "openresty" => Product::new("OpenResty", ver, None),
            "gunicorn" => Product::new("Gunicorn", ver, None),
            "werkzeug" => Product::new("Werkzeug", ver, None),
            _ => continue,
        };
        out.push(p);
    }
    out
}

/// FTP greetings: vsftpd, ProFTPD, FileZilla Server.
pub fn parse_ftp_banner(b: &str) -> Option<Product> {
    // Drop the reply code: "220 " or "220-" (multi-line reply).
    let b = match b.as_bytes() {
        [a, b2, c, b'-' | b' ', ..] if [a, b2, c].iter().all(|x| x.is_ascii_digit()) => &b[4..],
        _ => b,
    };
    let words: Vec<&str> = b.split(|c: char| c.is_whitespace() || c == '(' || c == ')').filter(|w| !w.is_empty()).collect();
    for (i, w) in words.iter().enumerate() {
        let next = words.get(i + 1).copied().unwrap_or("");
        match w.to_ascii_lowercase().as_str() {
            "vsftpd" => return Some(Product::new("vsftpd", next, None)),
            "proftpd" => return Some(Product::new("ProFTPD", next, None)),
            "filezilla" if words.get(i + 1) == Some(&"Server") => {
                let v = words.get(i + 2).copied().unwrap_or("");
                return Some(Product::new("FileZilla Server", v, None));
            }
            _ => {}
        }
    }
    None
}

/// SMTP greetings: Exim and Sendmail announce versions.
pub fn parse_smtp_banner(b: &str) -> Option<Product> {
    let words: Vec<&str> = b.split_whitespace().collect();
    for (i, w) in words.iter().enumerate() {
        let next = words.get(i + 1).map(|v| v.trim_end_matches([';', ',', '/'])).unwrap_or("");
        match *w {
            "Exim" => return Some(Product::new("Exim", next, None)),
            "Sendmail" => return Some(Product::new("Sendmail", next.split('/').next().unwrap_or(next), None)),
            _ => {}
        }
    }
    None
}

/// `5.7.44-log` -> MySQL 5.7.44; `5.5.5-10.11.6-MariaDB-0+deb12u1` -> MariaDB 10.11.6.
pub fn parse_mysql_version(v: &str) -> Option<Product> {
    if v.contains("MariaDB") {
        let parts: Vec<&str> = v.split('-').collect();
        // Newer MariaDB prefixes "5.5.5-" for old clients.
        let ver = if parts.first() == Some(&"5.5.5") { parts.get(1)? } else { parts.first()? };
        Some(Product::new("MariaDB", ver, None))
    } else {
        Some(Product::new("MySQL", v.split('-').next()?, None))
    }
}

// ---------------------------------------------------------------------------
// Small socket helpers
// ---------------------------------------------------------------------------

fn connect(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<TcpStream> {
    let s = TcpStream::connect_timeout(&SocketAddr::V4(SocketAddrV4::new(ip, port)), timeout).ok()?;
    s.set_read_timeout(Some(timeout * 2)).ok()?;
    s.set_write_timeout(Some(timeout * 2)).ok()?;
    Some(s)
}

/// Read up to `max` bytes, waiting at most about `timeout * 2` in total.
fn read_some(s: &mut TcpStream, max: usize, timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout * 2;
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    while out.len() < max && Instant::now() < deadline {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n.min(max - out.len())]);
                // Most probes get their whole answer in one packet.
                if n < buf.len() {
                    break;
                }
            }
        }
    }
    out
}

/// First non-empty line the service sends by itself.
fn read_line(s: &mut TcpStream, timeout: Duration) -> Option<String> {
    let data = read_some(s, 1024, timeout);
    let line = data.split(|&b| b == b'\n' || b == b'\r').find(|l| !l.is_empty())?;
    let text = clean(&String::from_utf8_lossy(line), 160);
    (!text.is_empty()).then_some(text)
}

/// An FTP reply, including multi-line replies ("220-..." ... "220 ...").
fn ftp_reply(s: &mut TcpStream, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout * 3;
    let mut text = String::new();
    while Instant::now() < deadline && text.len() < 4096 {
        let chunk = read_some(s, 1024, timeout);
        if chunk.is_empty() {
            break;
        }
        text.push_str(&String::from_utf8_lossy(&chunk));
        // Finished when the last line is "ddd text" (code followed by a space).
        let done = text.lines().last().is_some_and(|last| last.len() >= 4 && last.as_bytes()[..3].iter().all(u8::is_ascii_digit) && last.as_bytes()[3] == b' ');
        if done {
            break;
        }
    }
    let joined = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" | ");
    (!joined.is_empty()).then(|| clean(&joined, 200))
}

/// A string at a JSON path, e.g. `["version", "number"]`.
fn json_str(body: &str, path: &[&str]) -> Option<String> {
    let root: serde_json::Value = serde_json::from_str(body).ok()?;
    let mut cur = &root;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str().map(|s| clean(s, 40))
}

/// Remove control characters and cap the length (text from the network is untrusted).
pub fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect::<String>().trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(port: u16) -> Service {
        Service { ip: Ipv4Addr::LOCALHOST, port, name: "unknown", products: vec![], banner: None }
    }

    #[test]
    fn ssh() {
        assert_eq!(parse_ssh_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5").unwrap().label(), "OpenSSH 9.6p1");
        assert_eq!(parse_ssh_banner("SSH-2.0-dropbear_2022.83").unwrap().label(), "Dropbear SSH 2022.83");
        assert_eq!(parse_ssh_banner("SSH-2.0-OpenSSH_for_Windows_9.5").unwrap().label(), "OpenSSH 9.5");
        assert!(parse_ssh_banner("SSH-2.0-Cisco-1.25").is_none());
    }

    #[test]
    fn server_headers() {
        let v = parse_server_header("Apache/2.4.58 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3-4ubuntu2");
        let labels: Vec<_> = v.iter().map(Product::label).collect();
        assert_eq!(labels, ["Apache httpd 2.4.58", "OpenSSL 1.1.1f", "PHP 7.4.3"]);
        assert!(parse_server_header("nginx").is_empty());
        assert_eq!(parse_server_header("Jetty(9.4.53.v20231009)")[0].version, "9.4.53");
        assert_eq!(parse_server_header("MiniServ/2.105")[0].name, "Webmin");
    }

    #[test]
    fn ftp_smtp_mysql() {
        assert_eq!(parse_ftp_banner("220 (vsFTPd 3.0.5)").unwrap().label(), "vsftpd 3.0.5");
        assert_eq!(parse_ftp_banner("220 ProFTPD 1.3.5e Server (Debian)").unwrap().label(), "ProFTPD 1.3.5e");
        assert_eq!(parse_ftp_banner("220-FileZilla Server 0.9.60 beta").unwrap().version, "0.9.60");
        assert_eq!(parse_smtp_banner("220 mail.example.com ESMTP Exim 4.96 Mon, 2 Nov 2026").unwrap().label(), "Exim 4.96");
        assert_eq!(parse_mysql_version("5.5.5-10.11.6-MariaDB-0+deb12u1").unwrap().label(), "MariaDB 10.11.6");
        assert_eq!(parse_mysql_version("8.0.36-log").unwrap().label(), "MySQL 8.0.36");
    }

    #[test]
    fn json_paths_and_clean() {
        assert_eq!(json_str(r#"{"version":{"number":"7.10.2"}}"#, &["version", "number"]).as_deref(), Some("7.10.2"));
        assert_eq!(json_str("not json", &["x"]), None);
        assert_eq!(clean("a\u{1b}[31mb\r\n", 10), "a[31mb");
    }

    /// End-to-end on loopback: a fake FTP server that allows anonymous login.
    #[test]
    fn ftp_anonymous_detected() {
        use std::io::BufRead;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.write_all(b"220 (vsFTPd 3.0.3)\r\n").unwrap();
            let mut r = std::io::BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            s.write_all(b"331 Please specify the password.\r\n").unwrap();
            line.clear();
            r.read_line(&mut line).unwrap();
            s.write_all(b"230 Login successful.\r\n").unwrap();
        });
        let ctx = ProbeCtx::new(Duration::from_millis(500));
        let mut s = svc(port);
        let mut f = Vec::new();
        ftp_probe(&mut s, &mut f, &ctx);
        t.join().unwrap();
        assert_eq!(s.products[0].label(), "vsftpd 3.0.3");
        assert!(f.iter().any(|x| x.check.id == "PIS-0002"));
        assert!(f.iter().any(|x| x.check.id == "PIS-0013"));
    }

    /// End-to-end on loopback: a fake Redis without a password.
    #[test]
    fn redis_noauth_detected() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 64];
            let _ = s.read(&mut b);
            s.write_all(b"$60\r\n# Server\r\nredis_version:6.0.16\r\nredis_mode:standalone\r\n\r\n").unwrap();
        });
        let ctx = ProbeCtx::new(Duration::from_millis(500));
        let mut s = svc(port);
        let mut f = Vec::new();
        redis_probe(&mut s, &mut f, &ctx);
        t.join().unwrap();
        assert_eq!(s.name, "redis");
        assert_eq!(s.products[0].label(), "Redis 6.0.16");
        assert_eq!(f[0].check.id, "PIS-0003");
        assert_eq!(f[0].evidence, "INFO command answered without a password.");
    }

    /// End-to-end on loopback: an HTTP device with a cleartext login form.
    #[test]
    fn http_login_and_server_header() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 1024];
            let _ = s.read(&mut b);
            let body = "<form><input type=\"password\" name=pw></form>";
            let resp = format!("HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.59\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            s.write_all(resp.as_bytes()).unwrap();
        });
        let ctx = ProbeCtx::new(Duration::from_millis(500));
        let mut s = svc(port);
        let mut f = Vec::new();
        http_probe(&mut s, &mut f, &ctx, "http");
        t.join().unwrap();
        assert_eq!(s.name, "http");
        assert_eq!(s.banner.as_deref(), Some("Server: lighttpd/1.4.59"));
        assert_eq!(s.products[0].label(), "lighttpd 1.4.59");
        assert!(f.iter().any(|x| x.check.id == "PIS-0009"));
    }
}
