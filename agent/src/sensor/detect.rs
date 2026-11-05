//! Service detection on an open port, plus the configuration checks from checks.rs.
//!
//! Adapted from Proton IP Scanner (https://github.com/geekbrownbear/proton-network-scanner), GPL-3.0-or-later.
//! Proton turns detected software into CPE names for its CVE lookup; the
//! agent leaves CVE matching to the server, so only the name and version are kept here (for the
//! "Software version detected" finding). HTTP goes through ureq 2 with native-tls.
//!
//! How a port is probed is decided from its number alone, before any byte is sent ([`plan`]):
//!
//! | Port(s) | Method |
//! |---|---|
//! | printing: 515 (LPD), 9100 to 9102 (raw / JetDirect) | connect only. Nothing is ever written: a printer prints whatever arrives there |
//! | web ports (80, 8080, 443, 8443 ...) | HTTP(S) `GET /`: `Server` / `X-Powered-By` headers, page content |
//! | 21 | FTP greeting, then the documented `anonymous` login, then QUIT |
//! | 3306 | MySQL/MariaDB handshake packet (read only) |
//! | 6379 | Redis `INFO server` (read-only; also tells whether a password is required) |
//! | 5900 to 5903 | VNC version and offered security types (no authentication attempted) |
//! | 11211 | memcached `version` |
//! | 1883 | MQTT CONNECT without credentials, then DISCONNECT |
//! | 2375 | Docker Engine API `GET /version` |
//! | 9200 | Elasticsearch `GET /` |
//! | 23, 139, 445, 3389 | the open port is the finding; nothing written |
//! | other | read the greeting only. Bytes are sent only if the greeting identifies FTP |
//!
//! Proton sends a Redis command and then an HTTP request to any silent unknown service to
//! tell them apart. The agent does not: a silent service is left alone, so nothing is ever
//! written to a service that was not identified first, by its well-known port or its greeting.
//!
//! When a probe cannot finish (connect failure, timeout, short or unparseable reply), the
//! service is marked `inconclusive`, and the server keeps that port's earlier findings open
//! instead of taking the silence for a fix.
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
use super::ports::{is_print_port, service_name};

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
    /// A check that applies here could not finish, so "no finding" proves nothing.
    pub inconclusive: bool,
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
/// Plain-text services that always greet first. Silence on these means the read failed.
const GREETING_PORTS: [u16; 6] = [21, 22, 25, 110, 143, 587];

/// How a port is probed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Printing ports: the scan's connect is all; nothing is written or read.
    ConnectOnly,
    /// The open port itself is the finding (Telnet, SMB, RDP); nothing is written.
    Exposed,
    /// Read what the service sends by itself. Writes only after an FTP greeting.
    Greeting,
    Http(&'static str),
    Mysql,
    Redis,
    Vnc,
    Memcached,
    Mqtt,
    Ftp,
}

/// The probe for a port, decided by the port number alone.
pub fn plan(port: u16) -> Plan {
    match port {
        p if is_print_port(p) => Plan::ConnectOnly,
        p if HTTPS_PORTS.contains(&p) => Plan::Http("https"),
        p if HTTP_PORTS.contains(&p) => Plan::Http("http"),
        3306 => Plan::Mysql,
        6379 => Plan::Redis,
        5900..=5903 => Plan::Vnc,
        11211 => Plan::Memcached,
        1883 => Plan::Mqtt,
        21 => Plan::Ftp,
        23 | 139 | 445 | 3389 => Plan::Exposed,
        _ => Plan::Greeting,
    }
}

/// Identify the service on ip:port and run the checks that apply to it.
pub fn probe(ip: Ipv4Addr, port: u16, ctx: &ProbeCtx) -> (Service, Vec<Finding>) {
    probe_as(ip, port, plan(port), ctx)
}

pub(super) fn probe_as(ip: Ipv4Addr, port: u16, plan: Plan, ctx: &ProbeCtx) -> (Service, Vec<Finding>) {
    let mut svc = Service { ip, port, name: service_name(port), products: Vec::new(), banner: None, inconclusive: false };
    let mut findings = Vec::new();

    match plan {
        Plan::ConnectOnly => {}
        Plan::Exposed => match port {
            23 => findings.push(checks::TELNET.finding(port, "Port 23 accepts Telnet connections.")),
            3389 => findings.push(checks::RDP_EXPOSED.finding(port, "Port 3389 is open.")),
            _ => findings.push(checks::SMB_EXPOSED.finding(port, format!("Port {port} is open."))),
        },
        Plan::Greeting => greeting_probe(&mut svc, &mut findings, ctx),
        Plan::Http(scheme) => http_probe(&mut svc, &mut findings, ctx, scheme),
        Plan::Mysql => mysql_probe(&mut svc, &mut findings, ctx),
        Plan::Redis => redis_probe(&mut svc, &mut findings, ctx),
        Plan::Vnc => vnc_probe(&mut svc, &mut findings, ctx),
        Plan::Memcached => memcached_probe(&mut svc, &mut findings, ctx),
        Plan::Mqtt => mqtt_probe(&mut svc, &mut findings, ctx),
        Plan::Ftp => ftp_probe(&mut svc, &mut findings, ctx),
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

/// Any other port: read the greeting and recognise SSH / FTP / SMTP. Read-only unless the
/// greeting says FTP. A silent service is left alone.
fn greeting_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else {
        svc.inconclusive = true;
        return;
    };
    match read_line(&mut s, ctx.timeout) {
        Some(b) if b.starts_with("SSH-") => {
            svc.name = "ssh";
            svc.products.extend(parse_ssh_banner(&b));
            svc.banner = Some(b);
        }
        Some(b) if b.starts_with("220") => {
            let l = b.to_ascii_lowercase();
            if !l.contains("smtp") && (l.contains("ftp") || parse_ftp_banner(&b).is_some()) {
                // FTP on an unusual port: run the full FTP checks (fresh connection).
                drop(s);
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
        None => svc.inconclusive = GREETING_PORTS.contains(&svc.port),
    }
}

fn http_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx, scheme: &str) {
    let (ip, port) = (svc.ip, svc.port);
    let path = if port == 2375 { "/version" } else { "/" };
    let Some(resp) = http_get(ctx, scheme, ip, port, path) else {
        svc.inconclusive = true;
        return;
    };
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
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else {
        svc.inconclusive = true;
        return;
    };
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
        _ => svc.inconclusive = true,
    }
}

fn redis_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else {
        svc.inconclusive = true;
        return;
    };
    if s.write_all(b"INFO server\r\n").is_err() {
        svc.inconclusive = true;
        return;
    }
    let reply = String::from_utf8_lossy(&read_some(&mut s, 8192, ctx.timeout)).into_owned();
    if reply.contains("redis_version:") {
        svc.name = "redis";
        if let Some(v) = reply.lines().find_map(|l| l.strip_prefix("redis_version:")) {
            svc.products.push(Product::new("Redis", v.trim(), None));
        }
        findings.push(checks::REDIS_NOAUTH.finding(svc.port, "INFO command answered without a password."));
    } else if reply.starts_with("-NOAUTH") || reply.starts_with("-DENIED") || reply.contains("Authentication required") {
        // Password required, or protected mode refusing remote clients: positively safe.
        svc.name = "redis";
    } else {
        // Nothing, or an answer that is neither: the check could not tell.
        svc.inconclusive = true;
    }
}

fn vnc_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else {
        svc.inconclusive = true;
        return;
    };
    let hello = read_some(&mut s, 12, ctx.timeout);
    let Some(ver) = std::str::from_utf8(&hello).ok().filter(|v| v.starts_with("RFB ")) else {
        svc.inconclusive = true;
        return;
    };
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
        svc.inconclusive = true;
        return;
    }
    let reply = read_some(&mut s, 64, ctx.timeout);
    let complete = if minor < 7 { reply.len() >= 4 } else { !reply.is_empty() };
    if !complete {
        svc.inconclusive = true;
        return;
    }
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
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else {
        svc.inconclusive = true;
        return;
    };
    if s.write_all(b"version\r\n").is_err() {
        svc.inconclusive = true;
        return;
    }
    let reply = String::from_utf8_lossy(&read_some(&mut s, 256, ctx.timeout)).into_owned();
    if let Some(v) = reply.strip_prefix("VERSION ") {
        svc.name = "memcached";
        svc.products.push(Product::new("memcached", v.trim(), None));
        findings.push(checks::MEMCACHED_NOAUTH.finding(svc.port, "'version' answered without authentication."));
    } else if reply.is_empty() {
        svc.inconclusive = true;
    }
}

fn mqtt_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let Some(mut s) = connect(svc.ip, svc.port, ctx.timeout) else {
        svc.inconclusive = true;
        return;
    };
    // CONNECT, MQTT 3.1.1, clean session, keep-alive 60 s, client id "bw-sensor", no credentials.
    const CONNECT: [u8; 23] = [0x10, 21, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 60, 0, 9, b'b', b'w', b'-', b's', b'e', b'n', b's', b'o', b'r'];
    if s.write_all(&CONNECT).is_err() {
        svc.inconclusive = true;
        return;
    }
    let ack = read_some(&mut s, 4, ctx.timeout);
    // CONNACK: 0x20, length 2, flags, return code.
    if ack.first() != Some(&0x20) || ack.len() < 4 {
        svc.inconclusive = true;
        return;
    }
    svc.name = "mqtt";
    if ack[3] == 0 {
        findings.push(checks::MQTT_ANONYMOUS.finding(svc.port, "CONNECT without credentials was accepted (CONNACK 0)."));
    }
    let _ = s.write_all(&[0xE0, 0]); // DISCONNECT
}

fn ftp_probe(svc: &mut Service, findings: &mut Vec<Finding>, ctx: &ProbeCtx) {
    let greeting = connect(svc.ip, svc.port, ctx.timeout).and_then(|mut s| ftp_reply(&mut s, ctx.timeout).map(|g| (s, g)));
    let Some((mut s, greeting)) = greeting.filter(|(_, g)| g.starts_with("220")) else {
        // No connection, no greeting, or "421 too many users": the checks could not run.
        svc.inconclusive = true;
        return;
    };
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
    } else if reply.is_empty() {
        svc.inconclusive = true;
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
        Service { ip: Ipv4Addr::LOCALHOST, port, name: "unknown", products: vec![], banner: None, inconclusive: false }
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

    /// Printing ports get no active probe and no greeting probe: nothing is ever sent there.
    #[test]
    fn printing_ports_are_connect_only() {
        for port in [515, 9100, 9101, 9102] {
            assert_eq!(plan(port), Plan::ConnectOnly, "port {port}");
        }
        // Every preset port gets a plan, and none of the printing ones a writing plan.
        for port in super::super::ports::preset() {
            if is_print_port(port) {
                assert_eq!(plan(port), Plan::ConnectOnly);
            }
        }
        assert_eq!(plan(6379), Plan::Redis);
        assert_eq!(plan(22), Plan::Greeting);
    }

    /// A loopback server that records what the probe sent, staying silent.
    fn silent_server() -> (u16, std::thread::JoinHandle<Vec<u8>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut got = Vec::new();
            let _ = s.read_to_end(&mut got);
            got
        });
        (port, t)
    }

    /// The connect-only and greeting probes never write to a silent service (a raw print port
    /// would print it), and a silent unknown service is not "inconclusive".
    #[test]
    fn silent_services_receive_nothing() {
        let ctx = ProbeCtx::new(Duration::from_millis(300));
        for plan in [Plan::ConnectOnly, Plan::Greeting] {
            let (port, t) = silent_server();
            if plan == Plan::ConnectOnly {
                // The port scan's own connect, which is all a printing port gets.
                drop(TcpStream::connect(("127.0.0.1", port)).unwrap());
            }
            let (svc, findings) = probe_as(Ipv4Addr::LOCALHOST, port, plan, &ctx);
            assert_eq!(t.join().unwrap(), b"", "{plan:?} wrote to the service");
            assert!(findings.is_empty() && !svc.inconclusive, "{plan:?}");
        }
    }

    /// A probe that cannot finish marks the port inconclusive; a positive "safe" does not.
    #[test]
    fn failed_probes_are_inconclusive() {
        let ctx = ProbeCtx::new(Duration::from_millis(300));
        // Nothing listening.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        for plan in [Plan::Redis, Plan::Http("http"), Plan::Mysql, Plan::Ftp, Plan::Mqtt, Plan::Memcached, Plan::Vnc, Plan::Greeting] {
            let (svc, findings) = probe_as(Ipv4Addr::LOCALHOST, closed, plan, &ctx);
            assert!(svc.inconclusive, "{plan:?}");
            assert!(findings.is_empty(), "{plan:?}");
        }
        // Accepts, but never answers: the Redis check times out.
        let (port, t) = silent_server();
        let (svc, findings) = probe_as(Ipv4Addr::LOCALHOST, port, Plan::Redis, &ctx);
        assert!(svc.inconclusive && findings.is_empty());
        assert_eq!(t.join().unwrap(), b"INFO server\r\n");
        // Password required: checked and safe.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 64];
            let _ = s.read(&mut b);
            s.write_all(b"-NOAUTH Authentication required.\r\n").unwrap();
        });
        let (svc, findings) = probe_as(Ipv4Addr::LOCALHOST, port, Plan::Redis, &ctx);
        t.join().unwrap();
        assert!(!svc.inconclusive && findings.is_empty());
        assert_eq!(svc.name, "redis");
    }
}
