//! "Is this address alive?": ICMP echo through IcmpSendEcho (the API ping.exe uses, no admin
//! rights needed), with a TCP fallback.
//!
//! Adapted from Proton IP Scanner (https://github.com/geekbrownbear/proton-network-scanner), GPL-3.0-or-later.
//! The Linux ping-socket path is dropped.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use windows::Win32::NetworkManagement::IpHelper::{IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY};

/// Ports tried by [`tcp_probe`]: web, SSH, Windows file sharing / RPC / Remote Desktop, and the
/// Apple device sync port iPhones keep open.
const PROBE_PORTS: [u16; 7] = [80, 443, 22, 445, 135, 3389, 62078];

/// One ICMP echo request. `Ok(Some(rtt))` when the host answered, `Ok(None)` on timeout or
/// unreachable, `Err` when ICMP itself is unavailable.
pub fn icmp_ping(ip: Ipv4Addr, timeout: Duration) -> std::io::Result<Option<Duration>> {
    const PAYLOAD: &[u8; 16] = b"BearWatchSensor!";
    // One ICMP_ECHO_REPLY, the echoed payload and 8 bytes for an ICMP error (per Microsoft).
    let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8 + 16];
    // SAFETY: takes no arguments; the handle is checked and closed below.
    let handle = unsafe { IcmpCreateFile() }.map_err(std::io::Error::other)?;
    let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX).max(1);
    // IPAddr is the address in network byte order, i.e. the octets in memory order.
    let dest = u32::from_ne_bytes(ip.octets());
    let start = Instant::now();
    // SAFETY: handle is valid; request and reply pointers describe live buffers of those lengths.
    let count = unsafe {
        IcmpSendEcho(handle, dest, PAYLOAD.as_ptr().cast(), PAYLOAD.len() as u16, None, reply.as_mut_ptr().cast(), reply.len() as u32, timeout_ms)
    };
    let elapsed = start.elapsed();
    // SAFETY: closed exactly once.
    let _ = unsafe { IcmpCloseHandle(handle) };
    if count == 0 {
        return Ok(None);
    }
    // SAFETY: with count > 0 the buffer starts with an ICMP_ECHO_REPLY; the Vec<u8> may not be
    // aligned for it, so read it unaligned.
    let r: ICMP_ECHO_REPLY = unsafe { std::ptr::read_unaligned(reply.as_ptr().cast()) };
    // Status 0 = IP_SUCCESS, and the reply must come from the host we asked.
    if r.Status == 0 && r.Address == dest {
        // Windows reports whole milliseconds (0 for "<1 ms"); our own timing is finer then.
        let rtt = Duration::from_millis(u64::from(r.RoundTripTime));
        Ok(Some(if rtt.is_zero() { elapsed } else { rtt }))
    } else {
        Ok(None)
    }
}

/// Whether ICMP works here at all. Pinging 127.0.0.1 exercises the same code as a real scan.
pub fn icmp_available() -> bool {
    matches!(icmp_ping(Ipv4Addr::LOCALHOST, Duration::from_millis(500)), Ok(Some(_)))
}

/// Fallback liveness test: "connected" or "connection refused" on any of a few common ports
/// both mean something answered at that address.
pub fn tcp_probe(ip: Ipv4Addr, timeout: Duration) -> Option<Duration> {
    let per_port = (timeout / 3).max(Duration::from_millis(150));
    for port in PROBE_PORTS {
        let start = Instant::now();
        match TcpStream::connect_timeout(&SocketAddr::V4(SocketAddrV4::new(ip, port)), per_port) {
            Ok(_) => return Some(start.elapsed()),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Some(start.elapsed()),
            Err(_) => {}
        }
    }
    None
}
