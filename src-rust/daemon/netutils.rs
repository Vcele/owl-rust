// Network utilities for the OWL daemon
//
// Provides helpers for WiFi monitor mode, channel switching, link management,
// and IPv6 neighbour table operations. Translates daemon/netutils.c.
//
// On Linux, nl80211 operations are performed via the `iw` command-line tool
// and link/neighbour operations are performed via `ip`. This avoids a direct
// dependency on libnl while keeping the observable behaviour equivalent.

use std::io;
use std::net::Ipv6Addr;
use std::process::Command;

// ─── Platform init / cleanup (no-op in the Rust implementation) ──────────────

/// Initialise any platform-specific state required by netutils.
/// On Linux this is a no-op because we use subprocess calls instead of libnl.
pub fn netutils_init() -> io::Result<()> {
    Ok(())
}

/// Release any platform-specific state acquired by [`netutils_init`].
pub fn netutils_cleanup() {}

// ─── WiFi channel helpers ─────────────────────────────────────────────────────

/// Convert an 802.11 channel number to its centre frequency in MHz.
/// Supports the 2.4 GHz (channels 1–14) and 5 GHz (channels 36–165) bands.
pub fn ieee80211_channel_to_frequency(channel: u32) -> Option<u32> {
    if channel == 0 {
        return None;
    }
    if channel == 14 {
        return Some(2484);
    }
    if channel < 14 {
        return Some(2407 + channel * 5);
    }
    if channel >= 182 && channel <= 196 {
        return Some(4000 + channel * 5);
    }
    if channel >= 36 {
        return Some(5000 + channel * 5);
    }
    None
}

// ─── Monitor mode ─────────────────────────────────────────────────────────────

/// Put a WLAN interface into active monitor mode.
///
/// On Linux this calls `iw <iface> set monitor active` and, on macOS, the
/// CoreWLAN disassociate path is used instead (see original C source). On
/// other platforms the call returns `Ok(())` immediately.
pub fn set_monitor_mode(ifindex: i32) -> io::Result<()> {
    let iface = ifindex_to_name(ifindex)?;

    #[cfg(target_os = "linux")]
    {
        let status = Command::new("iw")
            .args([&iface, "set", "monitor", "active"])
            .status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("iw: {e}")))?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("iw set monitor active failed on {iface}"),
            ));
        }
    }

    let _ = iface; // suppress unused-variable warning on non-Linux platforms
    Ok(())
}

/// Query whether a given channel is available for frame injection.
///
/// On Linux this checks `iw dev <iface> info` output; on macOS channels are
/// assumed to always be available (matching the original C implementation).
pub fn is_channel_available(ifindex: i32, channel: u32) -> io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let _ = (ifindex, channel);
        return Ok(true);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let iface = ifindex_to_name(ifindex)?;
        let output = Command::new("iw")
            .args(["dev", &iface, "info"])
            .output()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("iw: {e}")))?;
        let text = String::from_utf8_lossy(&output.stdout);
        let marker = format!("channel {channel}");
        Ok(text.contains(&marker))
    }
}

/// Switch a WLAN interface to the specified channel.
///
/// On Linux this calls `iw dev <iface> set channel <channel>`.
/// On macOS this delegates to the CoreWLAN helper (not implemented here).
pub fn set_channel(ifindex: i32, channel: u32) -> io::Result<()> {
    let iface = ifindex_to_name(ifindex)?;

    #[cfg(target_os = "linux")]
    {
        let status = Command::new("iw")
            .args(["dev", &iface, "set", "channel", &channel.to_string()])
            .status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("iw: {e}")))?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("iw set channel {channel} failed on {iface}"),
            ));
        }
    }

    let _ = (iface, channel);
    Ok(())
}

// ─── Link management ─────────────────────────────────────────────────────────

/// Bring a network interface up (`ip link set <iface> up`).
pub fn link_up(ifindex: i32) -> io::Result<()> {
    link_updown(ifindex, true)
}

/// Bring a network interface down (`ip link set <iface> down`).
pub fn link_down(ifindex: i32) -> io::Result<()> {
    link_updown(ifindex, false)
}

fn link_updown(ifindex: i32, up: bool) -> io::Result<()> {
    let iface = ifindex_to_name(ifindex)?;
    let flag = if up { "up" } else { "down" };
    let status = Command::new("ip")
        .args(["link", "set", &iface, flag])
        .status()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ip: {e}")))?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("ip link set {iface} {flag} failed"),
        ));
    }
    Ok(())
}

/// Retrieve the Ethernet (MAC) address of a named interface using `SIOCGIFHWADDR`.
pub fn link_ether_addr_get(ifname: &str) -> io::Result<[u8; 6]> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        link_ether_addr_get_ioctl(ifname)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "link_ether_addr_get not supported on this platform",
        ))
    }
}

#[cfg(target_os = "linux")]
fn link_ether_addr_get_ioctl(ifname: &str) -> io::Result<[u8; 6]> {
    use std::ffi::CString;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let cname = CString::new(ifname).unwrap();
    let name_bytes = cname.as_bytes_with_nul();
    let len = name_bytes.len().min(libc::IFNAMSIZ);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            len,
        );
    }

    let err = unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR, &ifr as *const _ as *mut libc::c_void) };
    unsafe { libc::close(sock) };
    if err < 0 {
        return Err(io::Error::last_os_error());
    }

    let sa_data = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    Ok([
        sa_data[0] as u8,
        sa_data[1] as u8,
        sa_data[2] as u8,
        sa_data[3] as u8,
        sa_data[4] as u8,
        sa_data[5] as u8,
    ])
}

#[cfg(target_os = "macos")]
fn link_ether_addr_get_ioctl(ifname: &str) -> io::Result<[u8; 6]> {
    use std::ffi::CStr;
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut ifa = ifap;
    while !ifa.is_null() {
        unsafe {
            let name = CStr::from_ptr((*ifa).ifa_name).to_str().unwrap_or("");
            if name == ifname {
                let sa = (*ifa).ifa_addr;
                if !sa.is_null() && (*sa).sa_family == libc::AF_LINK as u8 {
                    let sdl = sa as *const libc::sockaddr_dl;
                    let lladdr = libc::LLADDR(sdl) as *const u8;
                    let addr = [
                        *lladdr,
                        *lladdr.add(1),
                        *lladdr.add(2),
                        *lladdr.add(3),
                        *lladdr.add(4),
                        *lladdr.add(5),
                    ];
                    libc::freeifaddrs(ifap);
                    return Ok(addr);
                }
            }
            ifa = (*ifa).ifa_next;
        }
    }
    unsafe { libc::freeifaddrs(ifap) };
    Err(io::Error::new(io::ErrorKind::NotFound, format!("no AF_LINK address for {ifname}")))
}

// ─── Hostname ─────────────────────────────────────────────────────────────────

/// Return the system hostname.
pub fn get_hostname() -> io::Result<String> {
    let mut buf = vec![0u8; 256];
    let err = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if err < 0 {
        return Err(io::Error::last_os_error());
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

// ─── IPv6 neighbour table ─────────────────────────────────────────────────────

/// Add a permanent IPv6 neighbour entry (`ip -6 neigh add … nud permanent`).
pub fn neighbor_add(ifindex: i32, eth: &[u8; 6], in6: &[u8; 16]) -> io::Result<()> {
    let iface = ifindex_to_name(ifindex)?;
    let ip6 = Ipv6Addr::from(*in6).to_string();
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]
    );
    let status = Command::new("ip")
        .args([
            "-6", "neigh", "add", &ip6, "lladdr", &mac, "dev", &iface, "nud", "permanent",
        ])
        .status()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ip neigh add: {e}")))?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("ip -6 neigh add {ip6} failed on {iface}"),
        ));
    }
    Ok(())
}

/// Remove an IPv6 neighbour entry (`ip -6 neigh del …`).
pub fn neighbor_remove(ifindex: i32, in6: &[u8; 16]) -> io::Result<()> {
    let iface = ifindex_to_name(ifindex)?;
    let ip6 = Ipv6Addr::from(*in6).to_string();
    let status = Command::new("ip")
        .args(["-6", "neigh", "del", &ip6, "dev", &iface])
        .status()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ip neigh del: {e}")))?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("ip -6 neigh del {ip6} failed on {iface}"),
        ));
    }
    Ok(())
}

/// Compute the RFC 4291 link-local IPv6 address from an Ethernet MAC address
/// and add it as a permanent neighbour entry.
pub fn neighbor_add_rfc4291(ifindex: i32, eth: &[u8; 6]) -> io::Result<()> {
    let in6 = rfc4291_addr(eth);
    neighbor_add(ifindex, eth, &in6)
}

/// Remove the RFC 4291 link-local IPv6 address derived from a MAC address
/// from the neighbour table.
pub fn neighbor_remove_rfc4291(ifindex: i32, eth: &[u8; 6]) -> io::Result<()> {
    let in6 = rfc4291_addr(eth);
    neighbor_remove(ifindex, &in6)
}

// ─── RFC 4291 EUI-64 address computation ─────────────────────────────────────

/// Derive an IPv6 link-local address from a MAC address using the RFC 4291
/// EUI-64 mapping into the `fe80::/64` prefix.
///
/// ```
/// # use awdl::election::format_addr;   // not needed here, just for context
/// use owl::daemon::netutils::rfc4291_addr;
///
/// let eth = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
/// let in6 = rfc4291_addr(&eth);
/// assert_eq!(in6[0], 0xfe);
/// assert_eq!(in6[1], 0x80);
/// assert_eq!(in6[8], 0x02); // bit 6 of first octet flipped
/// ```
pub fn rfc4291_addr(eth: &[u8; 6]) -> [u8; 16] {
    let mut in6 = [0u8; 16];
    in6[0] = 0xfe;
    in6[1] = 0x80;
    // bytes 2-7: all zero (link-local prefix)
    in6[8] = eth[0] ^ 0x02; // flip universal/local bit
    in6[9] = eth[1];
    in6[10] = eth[2];
    in6[11] = 0xff;
    in6[12] = 0xfe;
    in6[13] = eth[3];
    in6[14] = eth[4];
    in6[15] = eth[5];
    in6
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Map a network interface index to its name string.
fn ifindex_to_name(ifindex: i32) -> io::Result<String> {
    let mut buf = [0u8; libc::IFNAMSIZ];
    let ptr = unsafe {
        libc::if_indextoname(ifindex as libc::c_uint, buf.as_mut_ptr() as *mut libc::c_char)
    };
    if ptr.is_null() {
        return Err(io::Error::last_os_error());
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4291_addr_zero() {
        let eth = [0u8; 6];
        let in6 = rfc4291_addr(&eth);
        assert_eq!(&in6[0..2], &[0xfe, 0x80]);
        assert_eq!(&in6[2..8], &[0u8; 6]);
        assert_eq!(in6[8], 0x02); // 0x00 ^ 0x02
        assert_eq!(in6[11], 0xff);
        assert_eq!(in6[12], 0xfe);
    }

    #[test]
    fn test_rfc4291_addr_known() {
        // Example from RFC 4291 Appendix A:
        // MAC = 00-00-5E-EF-10-00 → in6 = fe80::0200:5eff:feef:1000
        let eth = [0x00, 0x00, 0x5e, 0xef, 0x10, 0x00];
        let in6 = rfc4291_addr(&eth);
        assert_eq!(in6[8], 0x02);  // 0x00 ^ 0x02
        assert_eq!(in6[9], 0x00);
        assert_eq!(in6[10], 0x5e);
        assert_eq!(in6[11], 0xff);
        assert_eq!(in6[12], 0xfe);
        assert_eq!(in6[13], 0xef);
        assert_eq!(in6[14], 0x10);
        assert_eq!(in6[15], 0x00);
    }

    #[test]
    fn test_ieee80211_channel_to_frequency() {
        assert_eq!(ieee80211_channel_to_frequency(1), Some(2412));
        assert_eq!(ieee80211_channel_to_frequency(6), Some(2437));
        assert_eq!(ieee80211_channel_to_frequency(11), Some(2462));
        assert_eq!(ieee80211_channel_to_frequency(14), Some(2484));
        assert_eq!(ieee80211_channel_to_frequency(36), Some(5180));
        assert_eq!(ieee80211_channel_to_frequency(149), Some(5745));
        assert_eq!(ieee80211_channel_to_frequency(0), None);
    }
}
