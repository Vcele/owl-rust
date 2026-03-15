// I/O state for the OWL daemon
//
// Handles pcap (WLAN injection/capture) and TUN/TAP (host interface) I/O.
// Translates daemon/io.c.

use std::io;
use std::os::unix::io::RawFd;

use pcap::{Active, Capture, Offline};

use super::netutils;

/// A pcap capture handle, which can be either a live device or a savefile.
pub enum WlanCapture {
    Live(Capture<Active>),
    File(Capture<Offline>),
}

impl WlanCapture {
    /// Inject a raw packet onto the WLAN interface (only supported on live captures).
    pub fn send_packet(&mut self, buf: &[u8]) -> Result<(), pcap::Error> {
        match self {
            WlanCapture::Live(cap) => cap.sendpacket(buf),
            WlanCapture::File(_) => Err(pcap::Error::PcapError(
                "cannot inject on offline capture".into(),
            )),
        }
    }

    /// Return the next captured packet, if any.
    pub fn next_packet(&mut self) -> Result<pcap::Packet<'_>, pcap::Error> {
        match self {
            WlanCapture::Live(cap) => cap.next_packet(),
            WlanCapture::File(cap) => cap.next_packet(),
        }
    }


}

/// Combined I/O state (WLAN + host TAP device).
pub struct IoState {
    pub wlan_handle: Option<WlanCapture>,
    pub wlan_ifname: String,
    pub wlan_ifindex: u32,
    pub host_ifname: String,
    pub host_ifindex: u32,
    /// MAC address shared by both the WLAN monitor interface and the TAP interface.
    pub if_ether_addr: [u8; 6],
    pub wlan_fd: Option<RawFd>,
    pub host_fd: Option<RawFd>,
    pub wlan_no_monitor_mode: bool,
    pub wlan_is_file: bool,
}

impl IoState {
    pub fn new() -> Self {
        IoState {
            wlan_handle: None,
            wlan_ifname: String::new(),
            wlan_ifindex: 0,
            host_ifname: String::new(),
            host_ifindex: 0,
            if_ether_addr: [0u8; 6],
            wlan_fd: None,
            host_fd: None,
            wlan_no_monitor_mode: false,
            wlan_is_file: false,
        }
    }
}

impl Default for IoState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── pcap helpers ────────────────────────────────────────────────────────────

/// Open a live WLAN interface in monitor mode (non-blocking), apply a BPF
/// filter that restricts to frames with the given BSSID in addr3, and return
/// the capture handle.
fn open_nonblocking_device(
    dev: &str,
    bssid_filter: &[u8; 6],
) -> Result<Capture<Active>, String> {
    let filter_str = format!(
        "wlan addr3 {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        bssid_filter[0],
        bssid_filter[1],
        bssid_filter[2],
        bssid_filter[3],
        bssid_filter[4],
        bssid_filter[5],
    );

    let inactive = Capture::from_device(dev)
        .map_err(|e| format!("pcap: unable to open device {dev}: {e}"))?
        .snaplen(65535)
        .promisc(true)
        .timeout(1);

    // On Linux monitor mode is activated via nl80211; on macOS via pcap rfmon.
    #[cfg(target_os = "macos")]
    let inactive = inactive.rfmon(true);

    let cap = inactive
        .open()
        .map_err(|e| format!("pcap: unable to activate device {dev}: {e}"))?;

    let mut cap = cap
        .setnonblock()
        .map_err(|e| format!("pcap: cannot set non-blocking mode: {e}"))?;

    if cap.direction(pcap::Direction::In).is_err() {
        log::warn!(
            "pcap: unable to monitor only incoming traffic on device {dev}"
        );
    }

    if cap.get_datalink() != pcap::Linktype(127) {
        // DLT_IEEE802_11_RADIO = 127
        return Err(format!(
            "pcap: device {dev} does not support radiotap headers"
        ));
    }

    cap.filter(&filter_str, true)
        .map_err(|e| format!("pcap: could not set filter: {e}"))?;

    Ok(cap)
}

/// Try to open `path` as a pcap savefile. Returns the capture handle.
fn open_savefile(path: &str) -> Result<Capture<Offline>, String> {
    let cap = Capture::from_file(path)
        .map_err(|e| format!("pcap: unable to open savefile {path}: {e}"))?;
    Ok(cap)
}

// ─── TUN/TAP helpers ─────────────────────────────────────────────────────────

/// Open (or create) a TAP device, set its MAC address, bring it up, and set
/// a reduced MTU. Returns the opened file descriptor.
///
/// On Linux this opens `/dev/net/tun` and configures an `IFF_TAP | IFF_NO_PI`
/// interface. On macOS it opens the first available `/dev/tapN` device.
fn open_tun(dev: &mut String, self_addr: &[u8; 6]) -> io::Result<RawFd> {
    #[cfg(target_os = "linux")]
    {
        open_tun_linux(dev, self_addr)
    }
    #[cfg(target_os = "macos")]
    {
        open_tun_macos(dev, self_addr)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TAP devices are not supported on this platform",
        ))
    }
}

#[cfg(target_os = "linux")]
fn open_tun_linux(dev: &mut String, self_addr: &[u8; 6]) -> io::Result<RawFd> {
    use libc::{c_int, c_void};
    use std::ffi::CString;

    const TUN_PATH: &[u8] = b"/dev/net/tun\0";
    let fd = unsafe { libc::open(TUN_PATH.as_ptr() as *const _, libc::O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // TUNSETIFF ioctl: configure TAP (layer 2) with no packet info header
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;
    if !dev.is_empty() {
        let name_bytes = dev.as_bytes();
        let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr() as *const libc::c_char,
                ifr.ifr_name.as_mut_ptr(),
                len,
            );
        }
    }

    // TUNSETIFF = 0x400454ca on Linux
    let tunsetiff: u64 = 0x400454ca;
    let err = unsafe { libc::ioctl(fd, tunsetiff, &ifr as *const _ as *mut c_void) };
    if err < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    // Update dev name from kernel
    let name_cstr =
        unsafe { std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr()) };
    *dev = name_cstr.to_string_lossy().into_owned();

    // Set non-blocking
    let one: c_int = 1;
    let err = unsafe { libc::ioctl(fd, libc::FIONBIO, &one as *const c_int as *mut c_void) };
    if err < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    // Open a socket for remaining ioctls
    let s = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if s < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    // Re-populate ifr_name for subsequent ioctls
    let cdev = CString::new(dev.as_str()).unwrap();
    unsafe {
        std::ptr::copy_nonoverlapping(
            cdev.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            cdev.as_bytes_with_nul().len().min(libc::IFNAMSIZ),
        );
    }

    // Set HW address (SIOCSIFHWADDR)
    ifr.ifr_ifru.ifru_hwaddr.sa_family = 1; // ARPHRD_ETHER
    unsafe {
        std::ptr::copy_nonoverlapping(
            self_addr.as_ptr(),
            ifr.ifr_ifru.ifru_hwaddr.sa_data.as_mut_ptr() as *mut u8,
            6,
        );
    }
    let err = unsafe { libc::ioctl(s, libc::SIOCSIFHWADDR, &ifr as *const _ as *mut c_void) };
    if err < 0 {
        log::error!("tun: unable to set HW address");
        unsafe { libc::close(fd); libc::close(s) };
        return Err(io::Error::last_os_error());
    }

    // Get + set interface flags (bring up)
    let err = unsafe { libc::ioctl(s, libc::SIOCGIFFLAGS, &ifr as *const _ as *mut c_void) };
    if err < 0 {
        unsafe { libc::close(fd); libc::close(s) };
        return Err(io::Error::last_os_error());
    }
    unsafe { ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16 }
    let err = unsafe { libc::ioctl(s, libc::SIOCSIFFLAGS, &ifr as *const _ as *mut c_void) };
    if err < 0 {
        log::error!("tun: unable to set up");
        unsafe { libc::close(fd); libc::close(s) };
        return Err(io::Error::last_os_error());
    }

    // Set MTU to 1450 (reduced to fit AWDL headers)
    ifr.ifr_ifru.ifru_mtu = 1450;
    let err = unsafe { libc::ioctl(s, libc::SIOCSIFMTU, &ifr as *const _ as *mut c_void) };
    if err < 0 {
        log::error!("tun: unable to set MTU");
        unsafe { libc::close(fd); libc::close(s) };
        return Err(io::Error::last_os_error());
    }

    unsafe { libc::close(s) };
    Ok(fd)
}

#[cfg(target_os = "macos")]
fn open_tun_macos(dev: &mut String, self_addr: &[u8; 6]) -> io::Result<RawFd> {
    for i in 0..16u32 {
        let tuntap = format!("/dev/tap{i}\0");
        let fd = unsafe { libc::open(tuntap.as_ptr() as *const _, libc::O_RDWR) };
        if fd < 0 {
            continue;
        }

        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            log::error!("fcntl error on /dev/tap{i}");
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        *dev = format!("tap{i}");

        let s = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        if s < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        // Set HW address via SIOCSIFLLADDR
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = dev.as_bytes();
        let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr() as *const libc::c_char,
                ifr.ifr_name.as_mut_ptr(),
                len,
            );
        }
        ifr.ifr_ifru.ifru_addr.sa_len = 6;
        ifr.ifr_ifru.ifru_addr.sa_family = libc::AF_LINK as u8;
        unsafe {
            std::ptr::copy_nonoverlapping(
                self_addr.as_ptr(),
                ifr.ifr_ifru.ifru_addr.sa_data.as_mut_ptr() as *mut u8,
                6,
            );
        }
        // SIOCSIFLLADDR = 0x8020693c on macOS
        let siocsiflladdr: u64 = 0x8020693c;
        let err = unsafe { libc::ioctl(s, siocsiflladdr, &ifr as *const _ as *mut libc::c_void) };
        if err < 0 {
            log::error!("tun: unable to set HW address");
            unsafe { libc::close(fd); libc::close(s) };
            return Err(io::Error::last_os_error());
        }

        // Set MTU
        ifr.ifr_ifru.ifru_mtu = 1450;
        let err = unsafe { libc::ioctl(s, libc::SIOCSIFMTU, &ifr as *const _ as *mut libc::c_void) };
        if err < 0 {
            log::error!("tun: unable to set MTU");
            unsafe { libc::close(fd); libc::close(s) };
            return Err(io::Error::last_os_error());
        }

        unsafe { libc::close(s) };
        return Ok(fd);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "tun: cannot open available tap device",
    ))
}

// ─── Public init/free ────────────────────────────────────────────────────────

/// Initialise the WLAN pcap capture (live or savefile) within `state`.
fn io_state_init_wlan(
    state: &mut IoState,
    wlan: &str,
    bssid_filter: &[u8; 6],
) -> Result<(), String> {
    state.wlan_ifname = wlan.to_owned();
    state.wlan_is_file = false;

    // First try to open the path as a pcap savefile.
    if let Ok(cap) = open_savefile(wlan) {
        log::info!("Using savefile instead of live device");
        state.wlan_handle = Some(WlanCapture::File(cap));
        state.wlan_is_file = true;
        state.wlan_ifindex = 0;
        return Ok(());
    }

    // Live device path.
    let ifindex = unsafe { libc::if_nametoindex(std::ffi::CString::new(wlan).unwrap().as_ptr()) };
    if ifindex == 0 {
        return Err(format!("No such interface: {wlan}"));
    }
    state.wlan_ifindex = ifindex;

    netutils::link_down(ifindex as i32)
        .map_err(|e| format!("Could not set link down on {wlan}: {e}"))?;

    if !state.wlan_no_monitor_mode {
        netutils::set_monitor_mode(ifindex as i32)
            .map_err(|e| format!("Could not put {wlan} in monitor mode: {e}"))?;
    }

    netutils::link_up(ifindex as i32)
        .map_err(|e| format!("Could not set link up on {wlan}: {e}"))?;

    let cap = open_nonblocking_device(wlan, bssid_filter)
        .map_err(|e| format!("Could not open device {wlan}: {e}"))?;

    state.if_ether_addr = netutils::link_ether_addr_get(wlan)
        .map_err(|e| format!("Could not get LLC address from {wlan}: {e}"))?;

    state.wlan_handle = Some(WlanCapture::Live(cap));
    Ok(())
}

/// Initialise the host TAP device within `state`.
fn io_state_init_host(state: &mut IoState, host: &str) -> Result<(), String> {
    if host.is_empty() {
        log::debug!("No host device given, starting without host device");
        return Ok(());
    }

    let mut dev = host.to_owned();
    let fd = open_tun(&mut dev, &state.if_ether_addr)
        .map_err(|e| format!("Could not open TAP device {host}: {e}"))?;

    state.host_ifname = dev.clone();
    state.host_fd = Some(fd);

    let ifindex = unsafe {
        libc::if_nametoindex(std::ffi::CString::new(dev.as_str()).unwrap().as_ptr())
    };
    if ifindex == 0 {
        return Err(format!("No such interface exists: {dev}"));
    }
    state.host_ifindex = ifindex;
    Ok(())
}

/// Initialise both WLAN and host I/O state.
pub fn io_state_init(
    state: &mut IoState,
    wlan: &str,
    host: &str,
    bssid_filter: &[u8; 6],
) -> Result<(), String> {
    io_state_init_wlan(state, wlan, bssid_filter)?;
    io_state_init_host(state, host)?;
    Ok(())
}

/// Release all resources held by `state`.
pub fn io_state_free(state: &mut IoState) {
    if let Some(fd) = state.host_fd.take() {
        unsafe { libc::close(fd) };
    }
    // The WlanCapture drop impl closes the pcap handle.
    state.wlan_handle = None;
}

// ─── Packet I/O ──────────────────────────────────────────────────────────────

/// Inject a raw 802.11 frame onto the WLAN interface via pcap.
pub fn wlan_send(state: &mut IoState, buf: &[u8]) -> io::Result<()> {
    match state.wlan_handle.as_mut() {
        None => Err(io::Error::new(io::ErrorKind::NotConnected, "no wlan handle")),
        Some(cap) => cap
            .send_packet(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string())),
    }
}

/// Write an Ethernet frame to the host TAP device.
pub fn host_send(state: &IoState, buf: &[u8]) -> io::Result<()> {
    match state.host_fd {
        None => Err(io::Error::new(io::ErrorKind::NotConnected, "no host fd")),
        Some(fd) => {
            let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

/// Read one Ethernet frame from the host TAP device.
/// On `EWOULDBLOCK`/`EAGAIN` returns 0 bytes (caller should retry later).
pub fn host_recv(state: &IoState, buf: &mut [u8]) -> io::Result<usize> {
    match state.host_fd {
        None => Err(io::Error::new(io::ErrorKind::NotConnected, "no host fd")),
        Some(fd) => {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    Ok(0)
                } else {
                    Err(e)
                }
            } else {
                Ok(n as usize)
            }
        }
    }
}
