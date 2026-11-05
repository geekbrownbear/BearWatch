//! Sensor mode: one PC per site scans its own local networks and reports what it finds, so
//! the server sees the printers, NAS boxes, cameras and unmanaged machines next to the PCs
//! that run the agent. The server picks the sensor and says how often to scan (Plan.sensor);
//! see run.rs for the schedule.
//!
//! Adapted from Proton IP Scanner (https://github.com/geekbrownbear/proton-network-scanner), GPL-3.0-or-later.
//! The scanner is Proton's: discovery, names, ports, MAC vendors and its 14 non-destructive
//! configuration checks. Each file in this folder says what was changed. What is new here is
//! the scope (which networks), the orchestration without Proton's GUI job/event machinery
//! (discover() follows Proton's), and the payload for the server.
//!
//! Scope: IPv4 networks of adapters that are up, private ranges only (10/8, 172.16/12,
//! 192.168/16), at most 4. An adapter network larger than a /22 is narrowed to the /24 around
//! this PC, so a /16 office LAN never turns into a 65,000-address sweep.
//!
//! Gentle on client networks: at most 64 threads (16 for the service checks), normal timeouts,
//! each port tried on every host before the next port, so no device gets a burst. Expect well
//! under two minutes for a /24.

pub mod adapters;
mod checks;
mod detect;
pub mod mac;
mod names;
mod ping;
mod ports;
mod vendor;

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::logger::log;
use adapters::Adapter;
use mac::Mac;

const MAX_NETWORKS: usize = 4;
/// Adapter networks with a shorter prefix than this are narrowed to the /24 around the PC.
const WIDEST_PREFIX: u8 = 22;
const MAX_THREADS: usize = 64;
const DETECT_THREADS: usize = 16;
const WORKER_STACK: usize = 512 * 1024;
const PING_TIMEOUT: Duration = Duration::from_millis(800);
const PING_ATTEMPTS: u8 = 2;
const PORT_TIMEOUT: Duration = Duration::from_millis(500);
const NAME_TIMEOUT: Duration = Duration::from_millis(700);
const SWEEP_WAIT: Duration = Duration::from_millis(2_500);

// Limits the server enforces. Everything is cut to fit here, so an upload never fails on them.
const MAX_HOSTS: usize = 4096;
const MAX_PORTS: usize = 200;
const MAX_ISSUES: usize = 50;
const MAX_UNCHECKED: usize = 200;
const LEN_ADDR: usize = 64;
const LEN_NAME: usize = 255;
const LEN_BANNER: usize = 300;
const LEN_TITLE: usize = 200;
const LEN_EVIDENCE: usize = 500;
const LEN_SOLUTION: usize = 1000;

// ---------------------------------------------------------------------------
// Payload (POST /api/agent/sensor). Field names are the server contract.
// ---------------------------------------------------------------------------

#[derive(Serialize, Debug)]
pub struct Payload {
    pub agent_version: &'static str,
    /// RFC 3339, UTC.
    pub started_at: String,
    pub duration_ms: u64,
    pub networks: Vec<Network>,
    pub hosts: Vec<Host>,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Network {
    pub interface: String,
    /// What was actually scanned, which may be narrower than the adapter's network.
    pub cidr: String,
    pub address: String,
    pub gateway: Option<String>,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct Host {
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub names: Names,
    pub workgroup: Option<String>,
    pub rtt_ms: Option<f64>,
    pub ports: Vec<Port>,
    pub issues: Vec<Issue>,
    /// Open ports where a check that applies could not finish (connect failure, timeout,
    /// short or unparseable reply). No issue there proves nothing, so the server keeps that
    /// port's earlier issues open. Sorted, no duplicates.
    pub unchecked_ports: Vec<u16>,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct Names {
    pub dns: Option<String>,
    pub netbios: Option<String>,
    pub mdns: Option<String>,
    pub upnp: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct Port {
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct Issue {
    pub id: String,
    pub port: u16,
    pub title: String,
    pub cvss: f64,
    pub evidence: String,
    pub solution: String,
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// One network to scan.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanNet {
    pub interface: String,
    /// This PC's address in it.
    pub addr: Ipv4Addr,
    /// The prefix that is scanned.
    pub prefix: u8,
    /// The adapter's own prefix (shorter than `prefix` when narrowed).
    pub adapter_prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub mac: Option<Mac>,
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    }
}

impl ScanNet {
    fn network(&self) -> u32 {
        u32::from(self.addr) & mask(self.prefix)
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network()), self.prefix)
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.prefix) == self.network()
    }

    /// Usable host addresses (network and broadcast skipped for blocks larger than /31).
    fn hosts(&self) -> impl Iterator<Item = Ipv4Addr> {
        let network = self.network();
        let broadcast = network | !mask(self.prefix);
        let (first, last) = if self.prefix >= 31 { (network, broadcast) } else { (network + 1, broadcast - 1) };
        (first..=last).map(Ipv4Addr::from)
    }
}

/// RFC 1918 only. Link-local (169.254/16) and carrier-grade NAT (100.64/10) fall outside it,
/// and so do public addresses: the sensor never scans anything it might not own.
pub fn is_private(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// Which networks to scan: private, de-duplicated, narrowed when wide, adapters with a gateway
/// (the "real" LAN) first, at most MAX_NETWORKS.
pub fn scope(adapters: &[Adapter]) -> Vec<ScanNet> {
    let mut out: Vec<ScanNet> = Vec::new();
    for a in adapters {
        for &(addr, adapter_prefix) in &a.ipv4 {
            if !is_private(addr) || adapter_prefix > 32 {
                continue;
            }
            let prefix = if adapter_prefix < WIDEST_PREFIX { 24 } else { adapter_prefix };
            let net = ScanNet { interface: a.name.clone(), addr, prefix, adapter_prefix, gateway: a.gateway, mac: a.mac };
            if !out.iter().any(|n| n.prefix == net.prefix && n.network() == net.network()) {
                out.push(net);
            }
        }
    }
    out.sort_by_key(|n| n.gateway.is_none());
    out.truncate(MAX_NETWORKS);
    out
}

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

/// Run `f(i)` for every i in 0..n on up to `threads` workers in background priority, and
/// collect the `Some` results. Work items are handed out by an atomic counter, so nothing is
/// queued up front.
fn pool<T: Send>(n: usize, threads: usize, f: impl Fn(usize) -> Option<T> + Sync) -> Vec<T> {
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::new());
    let work = || {
        crate::system::background(|| {
            let mut mine = Vec::new();
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                mine.extend(f(i));
            }
            if let Ok(mut r) = results.lock() {
                r.extend(mine);
            }
        })
    };
    std::thread::scope(|s| {
        let mut started = 0;
        for _ in 0..threads.clamp(1, MAX_THREADS).min(n.max(1)) {
            // If Windows refuses more threads, carry on with the ones we have.
            if std::thread::Builder::new().stack_size(WORKER_STACK).spawn_scoped(s, work).is_err() {
                break;
            }
            started += 1;
        }
        if started == 0 {
            work();
        }
    });
    results.into_inner().unwrap_or_else(|e| e.into_inner())
}

/// What discovery learned about one live address.
struct Found {
    ip: Ipv4Addr,
    rtt: Option<Duration>,
    mac: Option<Mac>,
    names: Names,
    workgroup: Option<String>,
}

/// Check one address (Proton's discover(), without the GUI bookkeeping). None if nobody is there.
fn discover(ip: Ipv4Addr, nets: &[ScanNet], icmp: bool) -> Option<Found> {
    let own = nets.iter().find(|n| n.addr == ip);
    let local_net = nets.iter().find(|n| n.contains(ip));

    // 1. Is it alive?
    let (mut alive, mut via_tcp, mut rtt) = (own.is_some(), false, None);
    if own.is_none() {
        for _ in 0..PING_ATTEMPTS {
            let reply = if icmp { ping::icmp_ping(ip, PING_TIMEOUT).ok().flatten() } else { ping::tcp_probe(ip, PING_TIMEOUT) };
            if reply.is_some() {
                (alive, via_tcp, rtt) = (true, !icmp, reply);
                break;
            }
        }
    }

    // 2. Hardware address. The ping above already made Windows ARP for it.
    let mac = match own {
        Some(n) => n.mac,
        None if local_net.is_some() => mac::lookup(ip),
        None => None,
    };
    // On our own network a real TCP answer always leaves an ARP entry. Without one, the
    // "answer" came from a firewall or proxy in between, not from a device at this address.
    if via_tcp && local_net.is_some() && mac.is_none() {
        (alive, rtt) = (false, None);
    }
    // A complete ARP entry means the device exists even though it ignored ping (typical for
    // Windows PCs with the firewall on).
    if !alive && mac.is_none() {
        return None;
    }

    // 3. Names, only for live hosts so dead addresses stay cheap. NetBIOS, mDNS, LLMNR, UPnP and
    //    a PTR query to the router go out together; the system resolver is asked only if the
    //    router had no answer (it can be slow when no PTR record exists).
    let query = names::NameQuery { netbios: true, device_names: true, dns_server: local_net.and_then(|n| n.gateway) };
    let asked = names::ask_device(ip, query, NAME_TIMEOUT);
    let dns = asked.router_dns.clone().or_else(|| names::reverse_dns(ip));
    let (netbios, workgroup) = asked.netbios.map(|n| (n.name, n.workgroup)).unwrap_or_default();
    Some(Found { ip, rtt, mac, names: Names { dns, netbios, mdns: asked.local_name, upnp: asked.upnp_name }, workgroup })
}

/// Scan this PC's networks now. Never fails: problems leave things out of the result.
pub fn scan() -> Payload {
    let started_at = crate::wua::now_rfc3339();
    let t = Instant::now();
    let nets = scope(&adapters::up());
    if nets.is_empty() {
        log("sensor scan: no private IPv4 network to scan");
    }
    for n in &nets {
        if n.prefix != n.adapter_prefix {
            log(&format!("sensor scan: {} is a /{} network; scanning only {} around this PC", n.interface, n.adapter_prefix, n.cidr()));
        }
    }
    let targets: Vec<Ipv4Addr> = nets.iter().flat_map(ScanNet::hosts).collect::<BTreeSet<_>>().into_iter().collect();
    log(&format!(
        "sensor scan started: {} ({} addresses)",
        nets.iter().map(|n| format!("{} on {}", n.cidr(), n.interface)).collect::<Vec<_>>().join(", "),
        targets.len()
    ));

    // Discovery, with the multicast name sweep running alongside it. Some devices (phones,
    // TVs, speakers) only answer multicast questions.
    let icmp = ping::icmp_available();
    let local: Vec<Ipv4Addr> = nets.iter().map(|n| n.addr).collect();
    let (mut found, swept) = std::thread::scope(|s| {
        let sweeper = (!targets.is_empty()).then(|| s.spawn(|| names::sweep(&targets, &local, SWEEP_WAIT)));
        let found = pool(targets.len(), MAX_THREADS, |i| discover(targets[i], &nets, icmp));
        (found, sweeper.and_then(|h| h.join().ok()).unwrap_or_default())
    });
    found.sort_by_key(|f| f.ip);
    for (ip, kind, name) in swept {
        if let Some(f) = found.iter_mut().find(|f| f.ip == ip) {
            let slot = match kind {
                names::SweepKind::Mdns => &mut f.names.mdns,
                names::SweepKind::Upnp => &mut f.names.upnp,
            };
            slot.get_or_insert(name);
        }
    }

    // Ports: each port on every host before the next port, so no device gets a burst.
    let live: Vec<Ipv4Addr> = found.iter().map(|f| f.ip).collect();
    let preset = ports::preset();
    let h = live.len().max(1);
    let mut open = pool(live.len() * preset.len(), MAX_THREADS, |i| {
        let (ip, port) = (*live.get(i % h)?, *preset.get(i / h)?);
        ports::probe(ip, port, PORT_TIMEOUT, true).map(|p| (ip, p))
    });
    open.sort_by_key(|(ip, p)| (*ip, p.port));

    // Services and configuration checks on each open port.
    let ctx = detect::ProbeCtx::new(PORT_TIMEOUT);
    let detected = pool(open.len(), DETECT_THREADS, |i| {
        let (ip, p) = &open[i];
        let (svc, findings) = detect::probe(*ip, p.port, &ctx);
        Some((*ip, p.banner.clone(), svc, findings))
    });

    let vendors = vendor::lookup_all(&found.iter().filter_map(|f| f.mac).collect::<Vec<_>>());
    let mut by_ip: HashMap<Ipv4Addr, Host> = found
        .into_iter()
        .map(|f| {
            let host = Host {
                ip: f.ip.to_string(),
                mac: f.mac.map(|m| m.to_string()),
                vendor: f.mac.and_then(|m| vendors.get(&m).cloned()),
                names: f.names,
                workgroup: f.workgroup,
                rtt_ms: f.rtt.map(|d| (d.as_secs_f64() * 100_000.0).round() / 100.0),
                ports: Vec::new(),
                issues: Vec::new(),
                unchecked_ports: Vec::new(),
            };
            (f.ip, host)
        })
        .collect();
    for (ip, scan_banner, svc, findings) in detected {
        if let Some(h) = by_ip.get_mut(&ip) {
            record(h, svc, scan_banner, findings);
        }
    }
    let mut hosts: Vec<(Ipv4Addr, Host)> = by_ip.into_iter().collect();
    hosts.sort_by_key(|(ip, _)| *ip);

    let networks = nets
        .iter()
        .map(|n| Network { interface: n.interface.clone(), cidr: n.cidr(), address: n.addr.to_string(), gateway: n.gateway.map(|g| g.to_string()) })
        .collect();
    let mut payload = Payload {
        agent_version: crate::VERSION,
        started_at,
        duration_ms: t.elapsed().as_millis() as u64,
        networks,
        hosts: hosts.into_iter().map(|(_, h)| h).collect(),
    };
    limit(&mut payload);
    let (ports, issues) = payload.hosts.iter().fold((0, 0), |(p, i), h| (p + h.ports.len(), i + h.issues.len()));
    log(&format!("sensor scan finished in {} s: {} hosts, {ports} open ports, {issues} findings", payload.duration_ms / 1000, payload.hosts.len()));
    payload
}

/// Add one probed port, its findings, and whether its checks finished, to a host.
fn record(h: &mut Host, svc: detect::Service, scan_banner: Option<String>, findings: Vec<checks::Finding>) {
    if svc.inconclusive {
        h.unchecked_ports.push(svc.port);
    }
    h.ports.push(Port { port: svc.port, service: svc.name.to_string(), banner: svc.banner.or(scan_banner) });
    h.issues.extend(findings.into_iter().map(|f| Issue {
        id: f.check.id.to_string(),
        port: f.port,
        title: f.check.title.to_string(),
        cvss: f.check.score,
        evidence: f.evidence,
        solution: f.check.solution.to_string(),
    }));
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Drop control characters and cut to at most `max` bytes on a char boundary. Bytes, not
/// chars, so the result fits whichever way the server counts.
fn fit(s: &mut String, max: usize) {
    if s.chars().any(char::is_control) {
        *s = s.chars().filter(|c| !c.is_control()).collect();
    }
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
}

fn fit_opt(s: &mut Option<String>, max: usize) {
    if let Some(v) = s.as_mut() {
        fit(v, max);
    }
}

/// Cut the payload to the server's limits. Issues are ranked worst first before cutting.
pub fn limit(p: &mut Payload) {
    p.networks.truncate(MAX_NETWORKS);
    for n in &mut p.networks {
        fit(&mut n.interface, LEN_NAME);
        fit(&mut n.cidr, LEN_ADDR);
        fit(&mut n.address, LEN_ADDR);
        fit_opt(&mut n.gateway, LEN_ADDR);
    }
    p.hosts.truncate(MAX_HOSTS);
    for h in &mut p.hosts {
        fit(&mut h.ip, LEN_ADDR);
        fit_opt(&mut h.mac, LEN_ADDR);
        fit_opt(&mut h.vendor, LEN_NAME);
        fit_opt(&mut h.workgroup, LEN_NAME);
        for n in [&mut h.names.dns, &mut h.names.netbios, &mut h.names.mdns, &mut h.names.upnp] {
            fit_opt(n, LEN_NAME);
        }
        h.ports.sort_by_key(|p| p.port);
        h.ports.truncate(MAX_PORTS);
        for port in &mut h.ports {
            fit(&mut port.service, LEN_NAME);
            fit_opt(&mut port.banner, LEN_BANNER);
        }
        h.issues.sort_by(|a, b| b.cvss.total_cmp(&a.cvss).then(a.port.cmp(&b.port)).then(a.id.cmp(&b.id)));
        h.issues.truncate(MAX_ISSUES);
        h.unchecked_ports.sort_unstable();
        h.unchecked_ports.dedup();
        h.unchecked_ports.truncate(MAX_UNCHECKED);
        for i in &mut h.issues {
            fit(&mut i.id, LEN_NAME);
            fit(&mut i.title, LEN_TITLE);
            fit(&mut i.evidence, LEN_EVIDENCE);
            fit(&mut i.solution, LEN_SOLUTION);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(name: &str, ipv4: &[(&str, u8)], gateway: Option<&str>) -> Adapter {
        Adapter {
            name: name.into(),
            mac: Some(Mac([0x00, 0x15, 0x5d, 1, 2, 3])),
            ipv4: ipv4.iter().map(|(a, p)| (a.parse().unwrap(), *p)).collect(),
            gateway: gateway.map(|g| g.parse().unwrap()),
        }
    }

    #[test]
    fn private_ranges_only() {
        for ip in ["10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.1", "192.168.1.5"] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["169.254.10.1", "100.64.0.1", "100.127.255.1", "172.15.0.1", "172.32.0.1", "192.169.0.1", "8.8.8.8", "127.0.0.1"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn scope_filters_narrows_and_caps() {
        let adapters = [
            adapter("VPN", &[("100.64.3.4", 10)], None),
            adapter("Wi-Fi", &[("10.1.2.3", 16)], None),
            adapter("Ethernet", &[("172.26.71.221", 24), ("169.254.1.1", 16)], Some("172.26.71.1")),
            adapter("Ethernet 2", &[("172.26.71.50", 24)], None), // same LAN: scanned once
            adapter("Lab", &[("192.168.8.9", 22), ("192.168.20.1", 23), ("192.168.30.1", 30)], None),
            adapter("Public", &[("203.0.113.5", 24)], Some("203.0.113.1")),
        ];
        let s = scope(&adapters);
        let cidrs: Vec<String> = s.iter().map(ScanNet::cidr).collect();
        // Gateway first, then adapter order; at most 4.
        assert_eq!(cidrs, ["172.26.71.0/24", "10.1.2.0/24", "192.168.8.0/22", "192.168.20.0/23"]);
        assert_eq!((s[1].prefix, s[1].adapter_prefix), (24, 16)); // /16 narrowed to the /24
        assert_eq!((s[2].prefix, s[2].adapter_prefix), (22, 22)); // /22 kept whole
        assert_eq!(s[0].gateway, Some(Ipv4Addr::new(172, 26, 71, 1)));
        assert_eq!(s[2].hosts().count(), 1022);
        assert_eq!(s[0].hosts().next(), Some(Ipv4Addr::new(172, 26, 71, 1)));
        assert_eq!(s[0].hosts().last(), Some(Ipv4Addr::new(172, 26, 71, 254)));
        let tiny = ScanNet { prefix: 32, adapter_prefix: 32, ..s[0].clone() };
        assert_eq!(tiny.hosts().collect::<Vec<_>>(), [Ipv4Addr::new(172, 26, 71, 221)]);
    }

    #[test]
    fn payload_shape() {
        let p = Payload {
            agent_version: "0.3.0",
            started_at: "2026-11-05T09:00:00Z".into(),
            duration_ms: 41234,
            networks: vec![Network { interface: "Ethernet".into(), cidr: "172.26.71.0/24".into(), address: "172.26.71.221".into(), gateway: None }],
            hosts: vec![Host {
                ip: "172.26.71.244".into(),
                mac: Some("bc:24:11:41:f4:f1".into()),
                names: Names { dns: Some("dockerdev01.lan".into()), ..Default::default() },
                rtt_ms: Some(0.4),
                ports: vec![Port { port: 22, service: "ssh".into(), banner: None }],
                issues: vec![Issue { id: "PIS-0003".into(), port: 6379, title: "t".into(), cvss: 9.3, evidence: "e".into(), solution: "s".into() }],
                unchecked_ports: vec![8443],
                ..Default::default()
            }],
        };
        let v = serde_json::to_value(&p).unwrap();
        let expected = serde_json::json!({
            "agent_version": "0.3.0",
            "started_at": "2026-11-05T09:00:00Z",
            "duration_ms": 41234,
            "networks": [{"interface": "Ethernet", "cidr": "172.26.71.0/24", "address": "172.26.71.221", "gateway": null}],
            "hosts": [{
                "ip": "172.26.71.244",
                "mac": "bc:24:11:41:f4:f1",
                "vendor": null,
                "names": {"dns": "dockerdev01.lan", "netbios": null, "mdns": null, "upnp": null},
                "workgroup": null,
                "rtt_ms": 0.4,
                "ports": [{"port": 22, "service": "ssh", "banner": null}],
                "issues": [{"id": "PIS-0003", "port": 6379, "title": "t", "cvss": 9.3, "evidence": "e", "solution": "s"}],
                "unchecked_ports": [8443]
            }]
        });
        assert_eq!(v, expected);
        // An empty host still has its names object and both arrays.
        let empty = serde_json::to_value(Host { ip: "10.0.0.1".into(), ..Default::default() }).unwrap();
        assert_eq!(empty["names"], serde_json::json!({"dns": null, "netbios": null, "mdns": null, "upnp": null}));
        assert_eq!(empty["ports"], serde_json::json!([]));
        assert_eq!(empty["issues"], serde_json::json!([]));
        assert_eq!(empty["unchecked_ports"], serde_json::json!([]));
    }

    #[test]
    fn fit_cuts_on_char_boundaries_and_strips_controls() {
        let mut s = "é".repeat(200); // 400 bytes
        fit(&mut s, 255);
        assert_eq!(s.len(), 254);
        assert!(s.chars().all(|c| c == 'é'));
        let mut b = "SSH-2.0\u{1b}[31m\r\nx".to_string();
        fit(&mut b, 300);
        assert_eq!(b, "SSH-2.0[31mx");
        let mut short = "abc".to_string();
        fit(&mut short, 3);
        assert_eq!(short, "abc");
        let mut emoji = "a\u{1F600}".to_string(); // 1 + 4 bytes
        fit(&mut emoji, 4);
        assert_eq!(emoji, "a");
    }

    #[test]
    fn limit_enforces_server_caps() {
        let issue = |cvss: f64, port: u16| Issue { id: "PIS-0012".into(), port, title: "x".repeat(300), cvss, evidence: "e".repeat(600), solution: "s".repeat(1200) };
        let host = Host {
            ip: "10.0.0.1".into(),
            vendor: Some("v".repeat(300)),
            names: Names { upnp: Some("n".repeat(300)), ..Default::default() },
            ports: (1..=250).rev().map(|p| Port { port: p, service: "unknown".into(), banner: Some("b".repeat(400)) }).collect(),
            issues: (0..60).map(|i| issue(if i == 59 { 9.3 } else { 0.0 }, i)).collect(),
            unchecked_ports: (1..=300).rev().chain([5, 5]).collect(),
            ..Default::default()
        };
        let mut p = Payload { agent_version: "0.3.0", started_at: String::new(), duration_ms: 0, networks: vec![], hosts: vec![host; 4100] };
        limit(&mut p);
        assert_eq!(p.hosts.len(), MAX_HOSTS);
        let h = &p.hosts[0];
        assert_eq!(h.ports.len(), MAX_PORTS);
        assert_eq!(h.ports[0].port, 1); // sorted before cutting
        assert_eq!(h.ports[0].banner.as_ref().unwrap().len(), LEN_BANNER);
        assert_eq!(h.issues.len(), MAX_ISSUES);
        assert_eq!(h.issues[0].cvss, 9.3); // worst kept first
        assert_eq!((h.issues[0].title.len(), h.issues[0].evidence.len(), h.issues[0].solution.len()), (LEN_TITLE, LEN_EVIDENCE, LEN_SOLUTION));
        assert_eq!(h.vendor.as_ref().unwrap().len(), LEN_NAME);
        assert_eq!(h.names.upnp.as_ref().unwrap().len(), LEN_NAME);
        assert_eq!(h.unchecked_ports, (1..=200).collect::<Vec<u16>>());
    }

    /// A check that could not finish puts its port in unchecked_ports; one that finished does not.
    #[test]
    fn probe_failure_lands_in_unchecked_ports() {
        let ctx = detect::ProbeCtx::new(Duration::from_millis(300));
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut h = Host { ip: "127.0.0.1".into(), ..Default::default() };
        let (svc, findings) = detect::probe_as(Ipv4Addr::LOCALHOST, closed, detect::Plan::Redis, &ctx);
        record(&mut h, svc, None, findings);
        // RDP: the open port is the finding, nothing can fail.
        let (svc, findings) = detect::probe_as(Ipv4Addr::LOCALHOST, 3389, detect::Plan::Exposed, &ctx);
        record(&mut h, svc, None, findings);
        let mut p = Payload { agent_version: "0.3.0", started_at: String::new(), duration_ms: 0, networks: vec![], hosts: vec![h] };
        limit(&mut p);
        let h = &p.hosts[0];
        assert_eq!(h.unchecked_ports, [closed]);
        assert_eq!(h.ports.len(), 2);
        assert_eq!(h.issues.len(), 1);
        assert_eq!(h.issues[0].id, "PIS-0010");
        let v = serde_json::to_value(h).unwrap();
        assert_eq!(v["unchecked_ports"], serde_json::json!([closed]));
    }
}
