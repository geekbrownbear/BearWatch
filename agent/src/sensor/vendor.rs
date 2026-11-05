//! Manufacturer ("vendor") lookup from the first half of a MAC address.
//!
//! Adapted from Proton IP Scanner (https://github.com/geekbrownbear/proton-network-scanner), GPL-3.0-or-later.
//! The list is Proton's `data/oui.tsv` (IEEE MA-L, MA-M and MA-S registries
//! via the oui-data package, BSD-2-Clause, see oui-LICENSE.txt), gzipped into the exe.
//!
//! Proton keeps the text in memory and builds a sorted index once. The agent is a service that
//! should stay small between scans, so here the list is unpacked once per scan, read in one
//! pass for just the MACs that were found, and dropped again.
//!
//! MA-M (7 hex digits) and MA-S (9 hex digits) blocks sit inside MA-L (6 digit) blocks owned by
//! the IEEE itself, so the longest matching prefix wins.

use std::collections::HashMap;
use std::io::Read;

use flate2::read::GzDecoder;

use super::mac::Mac;

/// `PREFIX<TAB>Vendor name` per line (prefix = 6, 7 or 9 hex digits), gzipped.
static OUI_GZ: &[u8] = include_bytes!("oui.tsv.gz");

const RANDOMIZED: &str = "Private (randomized) address";

/// The first `digits` hex digits of the MAC address as a number.
fn prefix(mac: &Mac, digits: usize) -> u64 {
    let all = mac.0.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)); // 12 hex digits
    all >> (4 * (12 - digits))
}

/// Vendor for each MAC, longest prefix first. Randomized addresses get a note instead, since
/// no registry lists them. MACs without a match are left out.
pub fn lookup_all(macs: &[Mac]) -> HashMap<Mac, String> {
    let mut out = HashMap::new();
    let mut text = String::new();
    if GzDecoder::new(OUI_GZ).read_to_string(&mut text).is_err() {
        return out;
    }
    lookup_in(&text, macs, &mut out);
    out
}

fn lookup_in(text: &str, macs: &[Mac], out: &mut HashMap<Mac, String>) {
    // (digits, prefix) -> the MACs that start with it.
    let mut wanted: HashMap<(usize, u64), Vec<Mac>> = HashMap::new();
    for m in macs {
        if m.is_randomized() {
            out.insert(*m, RANDOMIZED.to_string());
            continue;
        }
        for digits in [6, 7, 9] {
            wanted.entry((digits, prefix(m, digits))).or_default().push(*m);
        }
    }
    // Best match so far per MAC: (digits, name).
    let mut best: HashMap<Mac, (usize, &str)> = HashMap::new();
    for line in text.lines() {
        let Some((hex, name)) = line.split_once('\t') else { continue };
        let Ok(value) = u64::from_str_radix(hex, 16) else { continue };
        let Some(hits) = wanted.get(&(hex.len(), value)) else { continue };
        for m in hits {
            if best.get(m).is_none_or(|(d, _)| *d < hex.len()) {
                best.insert(*m, (hex.len(), name));
            }
        }
    }
    for (m, (_, name)) in best {
        out.insert(m, name.trim().to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_math() {
        let m = Mac([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
        assert_eq!(prefix(&m, 6), 0x123456);
        assert_eq!(prefix(&m, 7), 0x1234567);
        assert_eq!(prefix(&m, 9), 0x123456789);
    }

    #[test]
    fn longest_prefix_wins() {
        let text = "103456\tBig Block Owner\n1034567\tMedium Block\n103456789\tSmall Block\n";
        let small = Mac([0x10, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
        let medium = Mac([0x10, 0x34, 0x56, 0x7F, 0, 0]);
        let big = Mac([0x10, 0x34, 0x56, 0x00, 0, 0]);
        let mut out = HashMap::new();
        lookup_in(text, &[small, medium, big, Mac([0x20, 0, 0, 0, 0, 1])], &mut out);
        assert_eq!(out[&small], "Small Block");
        assert_eq!(out[&medium], "Medium Block");
        assert_eq!(out[&big], "Big Block Owner");
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn embedded_list() {
        let pi = Mac([0xB8, 0x27, 0xEB, 1, 2, 3]);
        let proxmox = Mac([0xBC, 0x24, 0x11, 0x41, 0xF4, 0xF1]);
        let random = Mac([0xDA, 0, 0, 0, 0, 1]);
        let v = lookup_all(&[pi, proxmox, random]);
        assert_eq!(v[&pi], "Raspberry Pi Foundation");
        assert_eq!(v[&proxmox], "Proxmox Server Solutions GmbH");
        assert_eq!(v[&random], RANDOMIZED);
    }
}
