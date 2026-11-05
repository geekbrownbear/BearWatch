//! MAC (hardware) addresses: the type, and the ARP lookup for devices on the local network.
//!
//! Adapted from Proton IP Scanner (https://github.com/geekbrownbear/proton-network-scanner), GPL-3.0-or-later.
//! Windows only here; the Linux /proc/net/arp reader is dropped.
//!
//! ARP only works inside the local network segment, so callers only ask about addresses in one
//! of this PC's own subnets. The ping just before the lookup already made Windows send the ARP
//! request, which is also how devices that drop ping are found.

use std::fmt;
use std::net::Ipv4Addr;

use windows::Win32::NetworkManagement::IpHelper::SendARP;

/// A 6-byte Ethernet or Wi-Fi hardware address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Bit 1 of the first byte set means "locally administered". Phones and laptops pick such
    /// random addresses for Wi-Fi privacy, so no vendor can be looked up.
    pub fn is_randomized(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// All-zero or broadcast addresses are not real devices.
    pub fn is_valid(&self) -> bool {
        self.0 != [0; 6] && self.0 != [0xff; 6]
    }
}

/// Lowercase with colons (`aa:bb:cc:dd:ee:ff`): the form the server stores and matches on.
impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

/// `SendARP` asks Windows to resolve the address (from its cache when it can). No admin
/// rights needed. Blocks for up to a few seconds when nobody answers.
pub fn lookup(ip: Ipv4Addr) -> Option<Mac> {
    // Room for 8 bytes as the API documents; the first 6 are the address.
    let mut buf = [0u8; 8];
    let mut len: u32 = buf.len() as u32;
    // SAFETY: buf/len describe a writable buffer; SendARP writes at most len bytes.
    let rc = unsafe { SendARP(u32::from_ne_bytes(ip.octets()), 0, buf.as_mut_ptr().cast(), &mut len) };
    if rc != 0 || len < 6 {
        return None;
    }
    let mac = Mac([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]]);
    mac.is_valid().then_some(mac)
}

#[cfg(test)]
mod tests {
    use super::Mac;

    #[test]
    fn lowercase_colon_form() {
        assert_eq!(Mac([0xBC, 0x24, 0x11, 0x41, 0xF4, 0x01]).to_string(), "bc:24:11:41:f4:01");
        assert!(!Mac([0; 6]).is_valid());
        assert!(!Mac([0xff; 6]).is_valid());
        assert!(Mac([0xda, 0, 0, 0, 0, 1]).is_randomized());
        assert!(!Mac([0xbc, 0x24, 0x11, 0, 0, 1]).is_randomized());
    }
}
