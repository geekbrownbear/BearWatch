//! TCP connect scan: open a normal connection to each port and close it again. Optionally read
//! the first line a service sends by itself (SSH, FTP and SMTP announce themselves).
//!
//! Adapted from Proton IP Scanner (https://github.com/geekbrownbear/proton-network-scanner), GPL-3.0-or-later.
//! Service names are short lowercase keys here (the server's vocabulary)
//! instead of Proton's display labels.
//!
//! Nothing is sent to the service in this step; the banner read is capped at 256 bytes and a
//! short timeout, and the text is cleaned before use.

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

/// Proton's vulnerability preset: common services plus databases, remote access, IoT and
/// container management ports.
pub const PRESET_VULN: &str = "21,22,23,25,53,80,81,110,111,135,139,143,443,445,465,548,554,587,631,993,995,1433,1521,1723,1883,2049,2375,3000,3306,3389,4443,5000,5001,5432,5900,5901,6379,7547,8000,8008,8080,8081,8088,8443,8888,9000,9100,9200,9443,11211,27017,32400";

/// Printing ports: LPD and raw/JetDirect. A printer prints whatever arrives there, so the scan
/// only connects and closes again; no banner read, no probe, nothing written.
const PRINT_PORTS: [u16; 4] = [515, 9100, 9101, 9102];

pub fn is_print_port(port: u16) -> bool {
    PRINT_PORTS.contains(&port)
}

/// One open port.
#[derive(Clone, Debug)]
pub struct OpenPort {
    pub port: u16,
    /// First line the service sent by itself, cleaned.
    pub banner: Option<String>,
}

/// PRESET_VULN as numbers.
pub fn preset() -> Vec<u16> {
    PRESET_VULN.split(',').filter_map(|p| p.parse().ok()).collect()
}

/// Connect to ip:port. `Some` only when the port is open.
pub fn probe(ip: Ipv4Addr, port: u16, timeout: Duration, grab_banner: bool) -> Option<OpenPort> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let banner = if grab_banner && !is_print_port(port) { read_banner(&mut stream) } else { None };
    Some(OpenPort { port, banner })
}

/// What a service says on its own within a short time.
fn read_banner(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_millis(700))).ok()?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    clean_banner(&buf[..n])
}

/// The first line, printable ASCII only, at most 80 characters.
fn clean_banner(bytes: &[u8]) -> Option<String> {
    let first_line = bytes.split(|&b| b == b'\n' || b == b'\r').find(|l| !l.is_empty())?;
    let text: String = first_line.iter().filter(|b| b.is_ascii_graphic() || **b == b' ').take(80).map(|&b| b as char).collect();
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// The usual service on a port (IANA registrations plus common real-world use), as a short
/// lowercase key. "unknown" when nothing fits.
pub fn service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 465 | 587 => "smtp",
        53 => "dns",
        80 | 81 | 591 | 8008 | 8000 | 8080 | 8081 | 8088 | 8888 | 3000 | 5000 => "http",
        110 | 995 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 | 993 => "imap",
        443 | 4443 | 8443 | 9443 | 5001 => "https",
        445 => "smb",
        548 => "afp",
        554 => "rtsp",
        515 => "lpd",
        631 => "ipp",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2375 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900..=5903 => "vnc",
        6379 => "redis",
        7547 => "tr-069",
        9000 => "http",
        9100..=9102 => "jetdirect",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        32400 => "plex",
        62078 => "apple-sync",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn finds_open_port_and_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"SSH-2.0-OpenSSH_9.9\x1b[31m\r\nmore").unwrap();
        });
        let open = probe(Ipv4Addr::LOCALHOST, port, Duration::from_secs(1), true).unwrap();
        assert_eq!(open.banner.as_deref(), Some("SSH-2.0-OpenSSH_9.9[31m"));
        t.join().unwrap();
    }

    #[test]
    fn preset_parses_and_every_port_has_a_name() {
        let p = preset();
        assert_eq!(p.len(), PRESET_VULN.split(',').count());
        assert!(p.contains(&6379) && p.contains(&22));
        for port in p {
            assert_ne!(service_name(port), "unknown", "port {port}");
        }
    }
}
