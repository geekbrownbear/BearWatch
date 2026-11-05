//! Device names. Several sources, because no single one works for every device:
//!
//! Adapted from Proton IP Scanner (https://github.com/geekbrownbear/proton-network-scanner), GPL-3.0-or-later.
//! Reverse DNS and the multicast socket use the Windows API directly
//! instead of the dns-lookup and socket2 crates.
//!
//! | Source | Answered by | How |
//! |---|---|---|
//! | Router DNS    | your router (names of DHCP clients) | PTR query sent straight to the gateway, UDP 53 |
//! | System DNS    | whatever resolver Windows uses, the hosts file | `GetNameInfoW` (only if the router had no answer) |
//! | NetBIOS       | Windows PCs, Samba servers, many NAS boxes | UDP 137 |
//! | mDNS          | iPhones, Macs, Linux (Avahi), printers, Chromecast, smart TVs | UDP 5353, unicast **and** a multicast sweep |
//! | LLMNR         | Windows PCs | UDP 5355 |
//! | UPnP / SSDP   | smart TVs, media players, routers, NAS, printers, consoles | UDP 1900 → device description XML (`friendlyName`) |
//!
//! Per device, the router-DNS, NetBIOS, mDNS, LLMNR and SSDP questions are
//! sent **at the same time** (small UDP packets straight to the device) and we
//! wait at most `timeout` for all of them together.
//!
//! In addition, [`sweep`] sends a few *multicast* mDNS and SSDP queries for the
//! whole range at the start of a scan. Some devices (many Android phones, TVs,
//! speakers) only answer multicast questions; their answers arrive as unicast
//! replies to us. (A host firewall may drop those replies; the per-device
//! unicast queries above still work then.)
//!
//! Security: names come from *other machines on the network* and must be
//! treated as untrusted input. Every name passes through [`sanitize`] or
//! [`sanitize_label`], which keep only safe ASCII characters and cap the
//! length, so a hostile device cannot inject control characters,
//! right-to-left tricks or markup into the dashboard. The
//! packet parsers check every length before reading and follow at most 16 DNS
//! compression pointers. UPnP descriptions are fetched **only** from the
//! device that announced them (the URL's host must be that device's IP),
//! read at most 64 KiB, and parsed with a simple text search — no XML parser.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// Longest name we keep (DNS labels are ≤63, NetBIOS names ≤15).
const MAX_NAME: usize = 64;

/// Name(s) found for one device.
#[derive(Clone, Debug, Default)]
pub struct NetbiosInfo {
    /// Computer name, e.g. `OFFICE-PC`.
    pub name: Option<String>,
    /// Workgroup or domain, e.g. `WORKGROUP`.
    pub workgroup: Option<String>,
}

/// Reverse DNS (PTR) lookup through the system resolver (`GetNameInfoW`).
///
/// Uses whatever Windows is configured with: its DNS servers and the hosts file.
pub fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    use windows::Win32::Networking::WinSock::{GetNameInfoW, socklen_t, AF_INET, IN_ADDR, IN_ADDR_0, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN};
    // Winsock must be started before GetNameInfoW; std does that the first time it creates
    // a socket, and the scan has made plenty by now. This one makes sure.
    drop(UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)));
    let sin = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(ip.octets()) } },
        sin_zero: [0; 8],
    };
    let mut host = [0u16; 1025];
    // SAFETY: sin is a valid SOCKADDR_IN of the given length; host is a writable buffer.
    let rc = unsafe {
        GetNameInfoW(std::ptr::from_ref(&sin).cast::<SOCKADDR>(), socklen_t(std::mem::size_of::<SOCKADDR_IN>() as i32), Some(&mut host), None, NI_NAMEREQD as i32)
    };
    if rc != 0 {
        return None;
    }
    let len = host.iter().position(|&c| c == 0).unwrap_or(host.len());
    let name = sanitize(String::from_utf16_lossy(&host[..len]).trim_end_matches('.'));
    // Some resolvers echo the address back instead of failing.
    (!name.is_empty() && name != ip.to_string()).then_some(name)
}

/// Names a device (or its router) told us (see [`ask_device`]).
#[derive(Clone, Debug, Default)]
pub struct DeviceNames {
    /// NetBIOS computer name and workgroup.
    pub netbios: Option<NetbiosInfo>,
    /// mDNS (Bonjour/Avahi) or LLMNR host name, without `.local`.
    pub local_name: Option<String>,
    /// Name the router's DNS has for this address (usually the DHCP host name).
    pub router_dns: Option<String>,
    /// UPnP "friendly name", e.g. `[TV] Samsung Q60` or `HP LaserJet M404`.
    pub upnp_name: Option<String>,
}

/// Which questions [`ask_device`] asks.
#[derive(Clone, Copy, Debug)]
pub struct NameQuery {
    pub netbios: bool,
    /// mDNS, LLMNR and UPnP.
    pub device_names: bool,
    /// Ask this DNS server (the router) for the PTR record.
    pub dns_server: Option<Ipv4Addr>,
}

/// Ask the device (and its router) for names over every enabled protocol at
/// once. Returns as soon as all have answered, or after `timeout`.
pub fn ask_device(ip: Ipv4Addr, q: NameQuery, timeout: Duration) -> DeviceNames {
    // Transaction ids: any values; replies must echo them.
    const NB_ID: u16 = 0x5052; // "PR"
    const MDNS_ID: u16 = 0x5053;
    const LLMNR_ID: u16 = 0x5054;
    const DNS_ID: u16 = 0x5056;

    // (socket, kind) for each query we managed to send.
    let mut pending: Vec<(UdpSocket, u8)> = Vec::new();
    let mut send = |to: Ipv4Addr, port: u16, packet: &[u8], kind: u8| {
        let Ok(sock) = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) else { return };
        // `connect` = only accept replies from that address and port.
        if sock.connect(SocketAddrV4::new(to, port)).is_ok()
            && sock.set_nonblocking(true).is_ok()
            && sock.send(packet).is_ok()
        {
            pending.push((sock, kind));
        }
    };
    if q.netbios {
        send(ip, 137, &nbstat_request(NB_ID), 0);
    }
    let ptr = ptr_query(ip);
    if q.device_names {
        // mDNS "legacy unicast" query: sent from a normal port straight to
        // the device's port 5353; responders answer us directly (RFC 6762 §6.7).
        send(ip, 5353, &with_id(&ptr, MDNS_ID), 1);
        send(ip, 5355, &with_id(&ptr, LLMNR_ID), 2);
        // UPnP 1.1 unicast M-SEARCH: the device answers with its description URL.
        send(ip, 1900, ssdp_search(Some(ip)).as_bytes(), 4);
    }
    if let Some(dns) = q.dns_server.filter(|d| *d != ip) {
        let mut query = with_id(&ptr, DNS_ID);
        query[2] = 0x01; // "recursion desired", like a normal resolver
        send(dns, 53, &query, 3);
    }

    let mut out = DeviceNames::default();
    let mut upnp_location = None;
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    while !pending.is_empty() && Instant::now() < deadline {
        pending.retain(|(sock, kind)| {
            let Ok(n) = sock.recv(&mut buf) else {
                return true; // nothing yet (or an ICMP error): keep waiting
            };
            let reply = &buf[..n];
            match kind {
                0 => out.netbios = parse_nbstat_reply(reply, NB_ID),
                1 => out.local_name = out.local_name.take().or_else(|| parse_ptr_reply(reply, MDNS_ID)),
                2 => out.local_name = out.local_name.take().or_else(|| parse_ptr_reply(reply, LLMNR_ID)),
                3 => out.router_dns = parse_ptr_reply(reply, DNS_ID),
                _ => upnp_location = parse_ssdp_location(reply),
            }
            false // answered: stop listening on this socket
        });
        // 15 ms polling keeps CPU near zero while waiting.
        std::thread::sleep(Duration::from_millis(15));
    }
    if let Some((port, path)) = upnp_location.as_deref().and_then(|l| description_url(l, ip)) {
        out.upnp_name = fetch_friendly_name(ip, port, &path, timeout.max(Duration::from_millis(800)));
    }
    out
}

/// Names found by a multicast [`sweep`] (applied to hosts as they are found).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepKind {
    /// mDNS host name → `Host::local_name`.
    Mdns,
    /// UPnP friendly name → `Host::upnp_name`.
    Upnp,
}

/// Multicast mDNS + SSDP sweep for the `targets` that lie in one of this
/// computer's networks (`local_nets` = our address in each network and the
/// prefix scanned there).
///
/// Sends at most a few dozen small packets, listens for `wait`, then fetches
/// UPnP descriptions from the devices that answered (8 at a time).
pub fn sweep(targets: &[Ipv4Addr], local_nets: &[(Ipv4Addr, u8)], wait: Duration) -> Vec<(Ipv4Addr, SweepKind, String)> {
    let wanted: std::collections::HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut found: Vec<(Ipv4Addr, SweepKind, String)> = Vec::new();
    let mut locations: HashMap<Ipv4Addr, (u16, String)> = HashMap::new();

    // One socket per local address, so multicast leaves on the right interface.
    let mut socks = Vec::new();
    for &(local, prefix) in local_nets {
        let Some(sock) = multicast_socket(local) else { continue };
        // mDNS: reverse (PTR) questions for the targets on this interface's network, 40 per
        // packet. Multicast stays on the link, so asking about other networks would be wasted.
        for chunk in on_network(targets, local, prefix).chunks(40) {
            let _ =
                sock.send_to(&multi_ptr_query(chunk, 0x5055), SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
        }
        // SSDP: one multicast search for UPnP root devices.
        let _ = sock.send_to(ssdp_search(None).as_bytes(), SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900));
        socks.push(sock);
    }
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 9000];
    while !socks.is_empty() && Instant::now() < deadline {
        for sock in &socks {
            while let Ok((n, SocketAddr::V4(from))) = sock.recv_from(&mut buf) {
                let ip = *from.ip();
                if !wanted.contains(&ip) {
                    continue;
                }
                let msg = &buf[..n];
                if from.port() == 1900 {
                    if let Some(loc) = parse_ssdp_location(msg).and_then(|l| description_url(&l, ip)) {
                        locations.entry(ip).or_insert(loc);
                    }
                } else {
                    for (addr, name) in mdns_names(msg) {
                        if wanted.contains(&addr) {
                            found.push((addr, SweepKind::Mdns, name));
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // Fetch UPnP descriptions (at most 64 devices, 8 in parallel).
    let list: Vec<(Ipv4Addr, (u16, String))> = locations.into_iter().take(64).collect();
    for chunk in list.chunks(8) {
        let names: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|(ip, (port, path))| {
                    s.spawn(move || (*ip, fetch_friendly_name(*ip, *port, path, Duration::from_millis(1500))))
                })
                .collect();
            handles.into_iter().filter_map(|h| h.join().ok()).collect()
        });
        for (ip, name) in names {
            if let Some(n) = name {
                found.push((ip, SweepKind::Upnp, n));
            }
        }
    }
    found.sort_by_key(|f| (f.0, f.1 as u8));
    found.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    found
}

/// The targets in the `/prefix` network that holds `local`.
fn on_network(targets: &[Ipv4Addr], local: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) };
    let net = u32::from(local) & mask;
    targets.iter().copied().filter(|t| u32::from(*t) & mask == net).collect()
}

/// UDP socket bound to `local`, sending multicast out of that interface.
fn multicast_socket(local: Ipv4Addr) -> Option<UdpSocket> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_MULTICAST_IF, SOCKET};
    let s = UdpSocket::bind(SocketAddrV4::new(local, 0)).ok()?;
    // IP_MULTICAST_IF takes the interface address in network byte order.
    let iface = local.octets();
    // SAFETY: the socket handle is valid for the lifetime of `s`; the option value is 4 bytes.
    let rc = unsafe { setsockopt(SOCKET(s.as_raw_socket() as usize), IPPROTO_IP.0, IP_MULTICAST_IF, Some(&iface)) };
    if rc != 0 {
        return None;
    }
    s.set_multicast_ttl_v4(255).ok()?;
    s.set_nonblocking(true).ok()?;
    Some(s)
}

/// SSDP M-SEARCH for UPnP root devices. Unicast searches (UPnP 1.1) carry
/// the device address in HOST and no MX; multicast ones use the group.
fn ssdp_search(unicast_to: Option<Ipv4Addr>) -> String {
    match unicast_to {
        Some(ip) => format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: {ip}:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\nUSER-AGENT: BearWatch UPnP/1.1\r\n\r\n"
        ),
        None => "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\nUSER-AGENT: BearWatch UPnP/1.1\r\n\r\n".into(),
    }
}

/// The `LOCATION:` header of an SSDP reply.
fn parse_ssdp_location(reply: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(reply.get(..reply.len().min(2048))?).ok()?;
    if !text.starts_with("HTTP/1.1 200") && !text.starts_with("NOTIFY") {
        return None;
    }
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("location").then(|| v.trim().to_string())
    })
}

/// Accept a description URL only if it is plain HTTP on **the device that
/// sent it** (prevents being steered to other hosts). Returns (port, path).
fn description_url(location: &str, ip: Ipv4Addr) -> Option<(u16, String)> {
    let rest = location.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (hostport, 80),
    };
    let ok_path = path.len() <= 200 && path.bytes().all(|b| b.is_ascii_graphic());
    (host.parse::<Ipv4Addr>().ok()? == ip && port > 0 && ok_path).then(|| (port, path.to_string()))
}

/// GET the UPnP description and return its first `<friendlyName>`.
fn fetch_friendly_name(ip: Ipv4Addr, port: u16, path: &str, timeout: Duration) -> Option<String> {
    let mut s = TcpStream::connect_timeout(&SocketAddr::V4(SocketAddrV4::new(ip, port)), timeout).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    let req =
        format!("GET {path} HTTP/1.0\r\nHost: {ip}:{port}\r\nUser-Agent: BearWatch\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).ok()?;
    let mut body = Vec::new();
    let deadline = Instant::now() + timeout * 2;
    let mut chunk = [0u8; 4096];
    while body.len() < 64 * 1024 && Instant::now() < deadline {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
        if body.windows(15).any(|w| w.eq_ignore_ascii_case(b"</friendlyName>")) {
            break; // we have what we need
        }
    }
    friendly_name(&String::from_utf8_lossy(&body))
}

/// Extract and clean `<friendlyName>…</friendlyName>` (case-insensitive).
fn friendly_name(xml: &str) -> Option<String> {
    let lower = xml.to_ascii_lowercase();
    let start = lower.find("<friendlyname>")? + "<friendlyname>".len();
    let end = start + lower.get(start..)?.find("</friendlyname>")?;
    let raw = xml.get(start..end)?;
    let decoded = raw
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    let name = sanitize_label(&decoded);
    (!name.is_empty()).then_some(name)
}

/// All (IP, host name) pairs in an mDNS message: PTR answers for reverse
/// names (`d.c.b.a.in-addr.arpa → host.local`) and A records (`host.local → IP`),
/// from the answer, authority and additional sections.
fn mdns_names(msg: &[u8]) -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    for (rtype, owner, rdata) in records(msg) {
        match rtype {
            12 => {
                if let (Some(ip), Some(target)) = (ip_from_reverse(&owner), rdata_name(msg, rdata)) {
                    let n = sanitize(target.trim_end_matches('.').trim_end_matches(".local"));
                    if !n.is_empty() {
                        out.push((ip, n));
                    }
                }
            }
            1 => {
                if let Some(b) = msg.get(rdata.0..rdata.0 + 4).filter(|_| rdata.1 == 4) {
                    let n = sanitize(owner.trim_end_matches('.').trim_end_matches(".local"));
                    if !n.is_empty() && !owner.ends_with(".arpa") {
                        out.push((Ipv4Addr::new(b[0], b[1], b[2], b[3]), n));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// `41.1.168.192.in-addr.arpa` → 192.168.1.41
fn ip_from_reverse(name: &str) -> Option<Ipv4Addr> {
    let rest = name.trim_end_matches('.').strip_suffix(".in-addr.arpa")?;
    let p: Vec<u8> = rest.split('.').map(|x| x.parse().ok()).collect::<Option<Vec<u8>>>()?;
    (p.len() == 4).then(|| Ipv4Addr::new(p[3], p[2], p[1], p[0]))
}

fn rdata_name(msg: &[u8], rdata: (usize, usize)) -> Option<String> {
    read_name(msg, rdata.0).map(|(n, _)| n)
}

/// Every resource record in a DNS message: (type, owner name, (rdata offset, rdata length)).
fn records(msg: &[u8]) -> Vec<(u16, String, (usize, usize))> {
    let mut out = Vec::new();
    let count =
        |i: usize| -> usize { msg.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]) as usize).unwrap_or(0) };
    let (qd, rr) = (count(4), count(6) + count(8) + count(10));
    let mut pos = 12;
    for _ in 0..qd.min(64) {
        match read_name(msg, pos) {
            Some((_, after)) => pos = after + 4,
            None => return out,
        }
    }
    for _ in 0..rr.min(64) {
        let Some((owner, after)) = read_name(msg, pos) else { break };
        let (Some(t), Some(l)) = (msg.get(after..after + 2), msg.get(after + 8..after + 10)) else { break };
        let rtype = u16::from_be_bytes([t[0], t[1]]);
        let rdlen = u16::from_be_bytes([l[0], l[1]]) as usize;
        let rdata = after + 10;
        if rdata + rdlen > msg.len() {
            break;
        }
        out.push((rtype, owner, (rdata, rdlen)));
        pos = rdata + rdlen;
    }
    out
}

/// One DNS message asking for the PTR records of several addresses.
fn multi_ptr_query(ips: &[Ipv4Addr], id: u16) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&(ips.len() as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for ip in ips {
        let q = ptr_query(*ip);
        p.extend_from_slice(&q[12..]); // question part only
    }
    p
}

/// A DNS query for the PTR record of `ip` (`d.c.b.a.in-addr.arpa`), id 0.
fn ptr_query(ip: Ipv4Addr) -> Vec<u8> {
    let o = ip.octets();
    let mut p = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]; // id, flags, 1 question
    for label in [o[3].to_string(), o[2].to_string(), o[1].to_string(), o[0].to_string()] {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    for label in ["in-addr", "arpa"] {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0, 12, 0, 1]); // type PTR, class IN
    p
}

fn with_id(q: &[u8], id: u16) -> Vec<u8> {
    let mut v = q.to_vec();
    if let Some(head) = v.get_mut(0..2) {
        head.copy_from_slice(&id.to_be_bytes());
    }
    v
}

/// Read a (possibly compressed) DNS name starting at `pos`. Returns the
/// dotted name and the position just after it in the original record.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None; // position after the name in the record we started in
    for _ in 0..16 {
        loop {
            let len = *msg.get(pos)? as usize;
            if len == 0 {
                end.get_or_insert(pos + 1);
                return Some((labels.join("."), end?));
            }
            if len & 0xC0 == 0xC0 {
                // Compression pointer: continue reading somewhere else.
                let target = ((len & 0x3F) << 8) | *msg.get(pos + 1)? as usize;
                end.get_or_insert(pos + 2);
                if target >= pos {
                    return None; // pointers must point backwards (no loops)
                }
                pos = target;
                break;
            }
            let label = msg.get(pos + 1..pos + 1 + len)?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            if labels.len() > 32 {
                return None;
            }
            pos += 1 + len;
        }
    }
    None // too many pointer jumps
}

/// Find the first PTR answer in a DNS/mDNS/LLMNR reply.
fn parse_ptr_reply(msg: &[u8], id: u16) -> Option<String> {
    // mDNS responders may send id 0; LLMNR and DNS must echo our id.
    let rid = u16::from_be_bytes([*msg.first()?, *msg.get(1)?]);
    if rid != id && rid != 0 {
        return None;
    }
    records(msg).into_iter().find_map(|(rtype, _, rdata)| {
        if rtype != 12 {
            return None;
        }
        let name = rdata_name(msg, rdata)?;
        let name = sanitize(name.trim_end_matches('.').trim_end_matches(".local"));
        (!name.is_empty()).then_some(name)
    })
}

/// Build the 50-byte NBSTAT request for the wildcard name `*`.
fn nbstat_request(txid: u16) -> [u8; 50] {
    let mut p = [0u8; 50];
    p[0..2].copy_from_slice(&txid.to_be_bytes());
    // flags 0, 1 question, 0 answers/authority/additional
    p[4..6].copy_from_slice(&1u16.to_be_bytes());
    // Name: length 32, then "*" + 15 NULs, each byte split into two nibbles
    // and encoded as 'A' + nibble ("first-level encoding", RFC 1002).
    p[12] = 32;
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    for (i, b) in raw.iter().enumerate() {
        p[13 + i * 2] = b'A' + (b >> 4);
        p[14 + i * 2] = b'A' + (b & 0x0f);
    }
    p[45] = 0; // end of name
    p[46..48].copy_from_slice(&0x0021u16.to_be_bytes()); // type NBSTAT
    p[48..50].copy_from_slice(&0x0001u16.to_be_bytes()); // class IN
    p
}

/// Parse an NBSTAT reply. Every index is bounds-checked with `get`, so a
/// truncated or malicious packet just yields `None`.
fn parse_nbstat_reply(pkt: &[u8], txid: u16) -> Option<NetbiosInfo> {
    // Header: id(2) flags(2) qd(2) an(2) ns(2) ar(2)
    if pkt.get(0..2)? != txid.to_be_bytes() || pkt.get(6..8)? == [0, 0] {
        return None;
    }
    // Skip the answer's name (a sequence of length-prefixed labels, or a
    // 2-byte compression pointer).
    let mut pos = 12;
    loop {
        let len = *pkt.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    // type(2) class(2) ttl(4) rdlength(2)
    if pkt.get(pos..pos + 2)? != [0x00, 0x21] {
        return None;
    }
    pos += 10;
    let count = *pkt.get(pos)? as usize;
    pos += 1;

    let mut info = NetbiosInfo::default();
    for i in 0..count {
        // Each entry: 15-byte name, 1-byte suffix, 2-byte flags.
        let entry = pkt.get(pos + i * 18..pos + i * 18 + 18)?;
        let suffix = entry[15];
        let is_group = entry[16] & 0x80 != 0;
        let name = sanitize(&String::from_utf8_lossy(&entry[..15]));
        if name.is_empty() || suffix != 0x00 {
            continue; // suffix 0x00 = workstation / workgroup name
        }
        if is_group {
            info.workgroup.get_or_insert(name);
        } else {
            info.name.get_or_insert(name);
        }
    }
    (info.name.is_some() || info.workgroup.is_some()).then_some(info)
}

/// Keep only characters that are safe to show and export: ASCII letters,
/// digits, `.`, `-`, `_` and single spaces; trim; cap the length.
pub fn sanitize(s: &str) -> String {
    let cleaned: String =
        s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ')).take(MAX_NAME).collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Like [`sanitize`] but also keeps the punctuation found in friendly device
/// names (`[TV] Samsung Q60 (55")` → `[TV] Samsung Q60 (55)`).
pub fn sanitize_label(s: &str) -> String {
    let cleaned: String =
        s.chars().filter(|c| c.is_ascii_alphanumeric() || " .-_()[]&+,:'#/".contains(*c)).take(MAX_NAME).collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Test hook: run every packet parser in this file on `b`.
#[cfg(test)]
pub fn fuzz_entry(b: &[u8]) {
    let _ = parse_nbstat_reply(b, 0x5052);
    let _ = parse_ptr_reply(b, 0x5053);
    let _ = parse_ptr_reply(b, 0);
    let _ = mdns_names(b);
    let _ = parse_ssdp_location(b);
    let _ = friendly_name(&String::from_utf8_lossy(b));
    for start in [0, 12, b.len() / 2] {
        let _ = read_name(b, start);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_questions_follow_the_scanned_network() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let targets = [ip("10.0.0.5"), ip("10.0.3.50"), ip("10.0.4.1"), ip("192.168.3.9")];
        // A /22 covers 10.0.0.0 to 10.0.3.255, so 10.0.3.50 is asked about from 10.0.0.2.
        assert_eq!(on_network(&targets, ip("10.0.0.2"), 22), [ip("10.0.0.5"), ip("10.0.3.50")]);
        assert_eq!(on_network(&targets, ip("10.0.0.2"), 24), [ip("10.0.0.5")]);
        assert_eq!(on_network(&targets, ip("192.168.0.2"), 22), [ip("192.168.3.9")]);
    }

    #[test]
    fn sanitize_strips_dangerous_chars() {
        assert_eq!(sanitize("=cmd|' /C calc'!A0"), "cmd C calcA0");
        assert_eq!(sanitize("evil\u{202e}gpj.exe"), "evilgpj.exe");
        assert_eq!(sanitize("OFFICE-PC      "), "OFFICE-PC");
        assert_eq!(sanitize(&"a".repeat(500)).len(), MAX_NAME);
        assert_eq!(sanitize("<script>x</script>"), "scriptxscript");
    }

    #[test]
    fn request_is_well_formed() {
        let p = nbstat_request(0x1234);
        assert_eq!(&p[0..2], &[0x12, 0x34]);
        assert_eq!(p[12], 32);
        assert_eq!(&p[13..15], b"CK"); // '*' = 0x2A → 'C','K'
        assert_eq!(&p[46..50], &[0, 0x21, 0, 1]);
    }

    /// Build a reply like a Windows PC sends.
    fn sample_reply() -> Vec<u8> {
        let mut r = vec![0x50, 0x52, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        r.push(32);
        r.extend_from_slice(&[b'A'; 32]);
        r.push(0);
        r.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0x41]);
        r.push(2);
        let mut e1 = *b"OFFICE-PC      \x00\x04\x00";
        e1[16] = 0x04; // unique
        let mut e2 = *b"WORKGROUP      \x00\x84\x00";
        e2[16] = 0x84; // group
        r.extend_from_slice(&e1);
        r.extend_from_slice(&e2);
        r.extend_from_slice(&[0u8; 6]);
        r
    }

    /// A real-shaped mDNS answer with a compression pointer.
    fn mdns_reply() -> Vec<u8> {
        let ip = Ipv4Addr::new(192, 168, 1, 41);
        let q = ptr_query(ip);
        let mut r = q.clone();
        r[2] = 0x84; // response, authoritative
        r[7] = 1; // one answer
        r.extend_from_slice(&[0xC0, 12]); // name → pointer to the question name
        r.extend_from_slice(&[0, 12, 0x80, 1, 0, 0, 0, 120]);
        let rdata = b"\x0cJohns-iPhone\x05local\x00";
        r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(rdata);
        r
    }

    #[test]
    fn parses_mdns_ptr() {
        assert_eq!(parse_ptr_reply(&mdns_reply(), 0x5053).as_deref(), Some("Johns-iPhone"));
    }

    #[test]
    fn dns_parser_survives_garbage() {
        let r = mdns_reply();
        for cut in 0..r.len() {
            let _ = parse_ptr_reply(&r[..cut], 0x5053);
        }
        // Pointer loop: a name that points to itself.
        let mut evil = r.clone();
        let at = evil.len() - 20;
        evil[at] = 0xC0;
        evil[at + 1] = at as u8;
        let _ = parse_ptr_reply(&evil, 0x5053);
        assert!(read_name(&[0xC0, 0x00], 0).is_none());
    }

    /// Tiny xorshift generator for the mutation test.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0.max(1);
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn between(&mut self, lo: u64, hi: u64) -> u64 {
            lo + self.next() % (hi - lo + 1)
        }
    }

    /// Mutation fuzzing: corrupt real-shaped replies in random places.
    #[test]
    fn mutated_replies_never_panic() {
        let mut rng = Rng(42);
        let seeds = [mdns_reply(), sample_reply()];
        for _ in 0..30_000 {
            let mut p = seeds[(rng.next() % 2) as usize].clone();
            for _ in 0..rng.between(1, 6) {
                let i = (rng.next() as usize) % p.len();
                p[i] = rng.next() as u8;
            }
            if rng.next().is_multiple_of(3) {
                p.truncate((rng.next() as usize) % (p.len() + 1));
            }
            fuzz_entry(&p);
        }
    }

    #[test]
    fn ask_device_times_out_quickly() {
        let t = Instant::now();
        let q = NameQuery { netbios: true, device_names: true, dns_server: Some(Ipv4Addr::new(127, 0, 0, 3)) };
        let n = ask_device(Ipv4Addr::new(127, 0, 0, 2), q, Duration::from_millis(300));
        assert!(t.elapsed() < Duration::from_secs(2));
        let _ = n;
    }

    #[test]
    fn upnp_helpers() {
        let reply = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.50:49152/desc.xml\r\nST: upnp:rootdevice\r\n\r\n";
        let loc = parse_ssdp_location(reply).unwrap();
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        assert_eq!(description_url(&loc, ip), Some((49152, "/desc.xml".into())));
        // A description URL pointing at another host is refused (no SSRF).
        assert_eq!(description_url("http://10.0.0.1/desc.xml", ip), None);
        assert_eq!(description_url("https://192.168.1.50/desc.xml", ip), None);
        assert_eq!(description_url("http://192.168.1.50/a b", ip), None);
        let xml = "<root><device><friendlyName>[TV] Samsung Q60 &amp; \u{1b}[31m<script></friendlyName><device><friendlyName>Inner</friendlyName></device></device></root>";
        assert_eq!(friendly_name(xml).as_deref(), Some("[TV] Samsung Q60 & [31mscript"));
        assert_eq!(friendly_name("<x/>"), None);
    }

    #[test]
    fn mdns_record_parsing() {
        assert_eq!(ip_from_reverse("41.1.168.192.in-addr.arpa"), Some(Ipv4Addr::new(192, 168, 1, 41)));
        assert_eq!(ip_from_reverse("999.1.168.192.in-addr.arpa"), None);
        let names = mdns_names(&mdns_reply());
        assert_eq!(names, vec![(Ipv4Addr::new(192, 168, 1, 41), "Johns-iPhone".to_string())]);
        let q = multi_ptr_query(&[Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)], 7);
        assert_eq!(&q[4..6], &[0, 2]);
        assert_eq!(records(&q).len(), 0); // questions only
    }

    /// End-to-end on this machine: a fake UPnP device answers a unicast
    /// M-SEARCH and serves its description; ask_device must return its name.
    #[test]
    fn upnp_friendly_name_end_to_end() {
        let Ok(udp) = UdpSocket::bind("127.0.0.1:1900") else { return }; // port in use: skip
        let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let hport = http.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut b = [0u8; 1500];
            if let Ok((_, from)) = udp.recv_from(&mut b) {
                let r = format!(
                    "HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:{hport}/rootDesc.xml\r\nST: upnp:rootdevice\r\n\r\n"
                );
                let _ = udp.send_to(r.as_bytes(), from);
            }
        });
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = http.accept() {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b);
                let _ = s.write_all(
                    b"HTTP/1.0 200 OK\r\n\r\n<root><device><friendlyName>Living Room TV</friendlyName></device></root>",
                );
            }
        });
        let q = NameQuery { netbios: false, device_names: true, dns_server: None };
        let n = ask_device(Ipv4Addr::LOCALHOST, q, Duration::from_millis(800));
        assert_eq!(n.upnp_name.as_deref(), Some("Living Room TV"));
    }

    /// A router's answer to our PTR query (recursion-available flags, compressed name).
    #[test]
    fn router_dns_reply_parsing() {
        {
            let ip = Ipv4Addr::new(192, 168, 1, 41);
            let mut reply = with_id(&ptr_query(ip), 0x5056);
            reply[2] = 0x81;
            reply[7] = 1;
            reply.extend_from_slice(&[0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 60]);
            let rdata = b"\x0agalaxy-s23\x03lan\x00";
            reply.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            reply.extend_from_slice(rdata);
            assert_eq!(parse_ptr_reply(&reply, 0x5056).as_deref(), Some("galaxy-s23.lan"));
        }
    }

    #[test]
    fn parses_reply() {
        let info = parse_nbstat_reply(&sample_reply(), 0x5052).unwrap();
        assert_eq!(info.name.as_deref(), Some("OFFICE-PC"));
        assert_eq!(info.workgroup.as_deref(), Some("WORKGROUP"));
    }

    #[test]
    fn rejects_bad_replies() {
        let r = sample_reply();
        assert!(parse_nbstat_reply(&r, 0x0000).is_none()); // wrong id
        for cut in 0..r.len() - 6 {
            // Truncated packets must never panic.
            let _ = parse_nbstat_reply(&r[..cut], 0x5052);
        }
        // Claimed entry count larger than the packet.
        let mut big = r.clone();
        big[56] = 255; // byte 56 = number of names
        assert!(parse_nbstat_reply(&big, 0x5052).is_none());
    }
}
