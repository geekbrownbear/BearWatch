//! This PC's network adapters, from GetAdaptersAddresses: the IPv4 networks the sensor scans,
//! and the MAC addresses the inventory reports (the server matches sensor hosts to managed PCs
//! with them). Proton IP Scanner uses the netdev crate for this; one Windows call does the
//! same job without another dependency.

use std::net::Ipv4Addr;

use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR, SOCKADDR_IN};

use super::mac::Mac;

const ERROR_BUFFER_OVERFLOW: u32 = 111;
const AF_UNSPEC: u32 = 0;

/// One adapter that is up, with its hardware address and IPv4 addresses.
#[derive(Clone, Debug)]
pub struct Adapter {
    pub name: String,
    pub mac: Option<Mac>,
    /// (address, on-link prefix length)
    pub ipv4: Vec<(Ipv4Addr, u8)>,
    pub gateway: Option<Ipv4Addr>,
}

/// An AF_INET socket address as an Ipv4Addr.
///
/// SAFETY: `sa` must be null or point to a SOCKADDR that is valid for its family's length.
unsafe fn ipv4(sa: *const SOCKADDR) -> Option<Ipv4Addr> {
    if sa.is_null() || (*sa).sa_family != AF_INET {
        return None;
    }
    let sin = sa.cast::<SOCKADDR_IN>();
    Some(Ipv4Addr::from(std::ptr::read_unaligned(sin).sin_addr.S_un.S_addr.to_ne_bytes()))
}

/// Adapters that are up, loopback excluded. Empty if the call fails.
pub fn up() -> Vec<Adapter> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // u64 elements keep the buffer 8-byte aligned for the structs Windows writes into it.
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut rc = ERROR_BUFFER_OVERFLOW;
    for _ in 0..4 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: buf holds at least `size` bytes; Windows updates size when it needs more.
        rc = unsafe { GetAdaptersAddresses(AF_UNSPEC, flags, None, Some(buf.as_mut_ptr().cast()), &mut size) };
        if rc != ERROR_BUFFER_OVERFLOW {
            break;
        }
    }
    if rc != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    // SAFETY: on success the buffer holds a linked list of adapters; every pointer in it points
    // into the same buffer, which lives until the end of this function.
    unsafe {
        while !cur.is_null() {
            let a = &*cur;
            cur = a.Next;
            if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }
            let mac = (a.PhysicalAddressLength == 6)
                .then(|| {
                    let p = a.PhysicalAddress;
                    Mac([p[0], p[1], p[2], p[3], p[4], p[5]])
                })
                .filter(Mac::is_valid);
            let mut ipv4s = Vec::new();
            let mut ua = a.FirstUnicastAddress;
            while !ua.is_null() {
                if let Some(ip) = ipv4((*ua).Address.lpSockaddr) {
                    ipv4s.push((ip, (*ua).OnLinkPrefixLength));
                }
                ua = (*ua).Next;
            }
            let mut gateway = None;
            let mut ga = a.FirstGatewayAddress;
            while !ga.is_null() && gateway.is_none() {
                gateway = ipv4((*ga).Address.lpSockaddr).filter(|g| !g.is_unspecified());
                ga = (*ga).Next;
            }
            let name = a.FriendlyName.to_string().unwrap_or_default();
            out.push(Adapter { name, mac, ipv4: ipv4s, gateway });
        }
    }
    out
}

/// MAC addresses of the adapters that are up: lowercase colon form, sorted, no duplicates.
pub fn macs() -> Vec<String> {
    let mut m: Vec<String> = up().iter().filter_map(|a| a.mac).map(|m| m.to_string()).collect();
    m.sort();
    m.dedup();
    m
}
