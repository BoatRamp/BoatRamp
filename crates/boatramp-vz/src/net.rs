//! Guest networking helpers — **pure and cross-platform**.
//!
//! Virtualization.framework attaches each VM to Apple's `vmnet` NAT network via
//! `VZNATNetworkDeviceAttachment`, so — unlike the KVM backend — boatramp does
//! **not** create host taps or bridges. What it still owns is the guest's MAC
//! (derived deterministically from its IP, matching `IpPool::mac_for`, so a
//! restart re-derives the same address) and the parse into the 6 bytes a
//! `VZMACAddress` wants.

use std::net::Ipv4Addr;

/// A stable, locally-administered unicast MAC derived from `ip`
/// (`02:00:<the four IPv4 octets>`). Byte-for-byte the same scheme as
/// `boatramp_core::ipam::IpPool::mac_for`, so the KVM and macOS backends agree on
/// a guest's MAC and a restore/reschedule keeps it stable. The `02` prefix sets
/// the locally-administered bit and clears the multicast bit.
pub fn mac_for(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("02:00:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
}

/// Parse an `aa:bb:cc:dd:ee:ff` MAC string into 6 bytes (for `VZMACAddress`).
/// Missing/short octets default to 0; extra octets past 6 are ignored.
pub fn parse_mac(mac: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (i, octet) in mac.split(':').take(6).enumerate() {
        out[i] = u8::from_str_radix(octet, 16).unwrap_or(0);
    }
    out
}

/// The MAC bytes for a guest IP in one step (`mac_for` ∘ `parse_mac`).
pub fn mac_bytes_for(ip: Ipv4Addr) -> [u8; 6] {
    parse_mac(&mac_for(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_encodes_the_four_octets_after_the_02_00_prefix() {
        assert_eq!(mac_for(Ipv4Addr::new(10, 0, 0, 5)), "02:00:0a:00:00:05");
        assert_eq!(
            mac_for(Ipv4Addr::new(192, 168, 64, 200)),
            "02:00:c0:a8:40:c8"
        );
    }

    #[test]
    fn parse_mac_round_trips_mac_for() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        assert_eq!(
            parse_mac(&mac_for(ip)),
            [0x02, 0x00, 0x0a, 0x00, 0x00, 0x05]
        );
    }

    #[test]
    fn mac_bytes_for_composes() {
        assert_eq!(
            mac_bytes_for(Ipv4Addr::new(192, 168, 64, 200)),
            [0x02, 0x00, 0xc0, 0xa8, 0x40, 0xc8]
        );
    }

    #[test]
    fn parse_mac_tolerates_short_input() {
        assert_eq!(parse_mac("02:00"), [0x02, 0x00, 0, 0, 0, 0]);
        assert_eq!(parse_mac(""), [0, 0, 0, 0, 0, 0]);
    }
}
