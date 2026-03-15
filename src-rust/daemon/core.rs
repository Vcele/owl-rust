// Daemon core: event loop, frame dispatch, and timer management
//
// Translates daemon/core.c, replacing libev with tokio.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};

use awdl::channel::{awdl_chan_num, AWDL_CHANSEQ_LENGTH};
use awdl::election::ElectionState;
use awdl::frame::AwdlActionType;
use awdl::ieee80211::ieee80211_tu_to_usec;
use awdl::peers::{peers_remove_old, Peer};
use awdl::rx::{rx_action, rx_data, RxResult};
use awdl::schedule::{
    can_send_in, can_send_unicast_in, is_multicast_eaw, AWDL_MULTICAST_GUARD_TU,
    AWDL_UNICAST_GUARD_TU,
};
use awdl::state::{clock_time_us, AwdlState, Ieee80211State};
use awdl::tx::{awdl_init_full_action_frame, awdl_init_full_data_frame};
use awdl::wire::Buf;

use super::io::{self, IoState};
use super::netutils;

// ─── Ethernet constants ───────────────────────────────────────────────────────

const ETHER_LENGTH: usize = 14;
const ETHER_DST_OFFSET: usize = 0;
const ETHER_SRC_OFFSET: usize = 6;
const ETHER_ETHERTYPE_OFFSET: usize = 12;
const ETHER_MAX_LEN: usize = 1514;

const MULTICAST_BIT: u8 = 0x01;

// Multicast TX queue size, matching the C implementation
const TX_QUEUE_MULTICAST_SIZE: usize = 16;

// ─── Daemon state ─────────────────────────────────────────────────────────────

/// Combined state for the OWL daemon (I/O + AWDL + IEEE 802.11).
pub struct DaemonState {
    pub io: IoState,
    pub awdl: AwdlState,
    pub ieee80211: Ieee80211State,
    /// Next pending unicast frame to be transmitted.
    pub next_unicast: Option<Vec<u8>>,
    /// Pending multicast frames.
    pub tx_queue_multicast: VecDeque<Vec<u8>>,
    /// Optional pcap savefile path for dumping unknown frames.
    pub dump: Option<String>,
}

impl DaemonState {
    pub fn new(awdl: AwdlState, io: IoState, dump: Option<String>) -> Self {
        DaemonState {
            io,
            awdl,
            ieee80211: Ieee80211State::new(),
            next_unicast: None,
            tx_queue_multicast: VecDeque::with_capacity(TX_QUEUE_MULTICAST_SIZE),
            dump,
        }
    }
}

// ─── Neighbour callbacks ──────────────────────────────────────────────────────

fn awdl_neighbor_add(peer: &Peer, host_ifindex: i32) {
    if let Err(e) = netutils::neighbor_add_rfc4291(host_ifindex, &peer.addr) {
        log::warn!("neighbor_add_rfc4291 failed: {e}");
    }
}

fn awdl_neighbor_remove(peer: &Peer, host_ifindex: i32) {
    if let Err(e) = netutils::neighbor_remove_rfc4291(host_ifindex, &peer.addr) {
        log::warn!("neighbor_remove_rfc4291 failed: {e}");
    }
}

// ─── Frame receive path ───────────────────────────────────────────────────────

/// Process a single captured 802.11 radiotap frame.
pub fn awdl_receive_frame(state: &mut DaemonState, raw: &[u8]) {
    if raw.len() < 4 {
        return;
    }

    // Radiotap header length is at bytes 2-3 (little-endian u16)
    let radiotap_len = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    if raw.len() < radiotap_len + 24 {
        return;
    }

    // 802.11 header starts after radiotap
    let hdr = &raw[radiotap_len..];

    // FC byte 0: frame type at bits[3:2] (0=management, 2=data)
    let frame_type = (hdr[0] >> 2) & 0x03;

    // Extract addr1 (dst, bytes 4-9) and addr2 (src, bytes 10-15)
    let dst: [u8; 6] = hdr[4..10].try_into().unwrap_or([0u8; 6]);
    let src: [u8; 6] = hdr[10..16].try_into().unwrap_or([0u8; 6]);

    // Payload starts after 24-byte 802.11 header
    let payload = &raw[radiotap_len + 24..];
    let frame = Buf::from_bytes(payload.to_vec());
    let now = clock_time_us();

    // RSSI from radiotap (simplified: not extracted here, use 0)
    let rssi: i8 = 0;

    if frame_type == 0 {
        // Management frame – attempt to parse as AWDL action frame
        match rx_action(&frame, rssi, now, &src, &dst, &mut state.awdl) {
            RxResult::Ok => {
                state.awdl.stats.rx_action += 1;
                // Notify neighbour table of new/updated peer
                let host_ifindex = state.io.host_ifindex as i32;
                awdl_neighbor_add(
                    &state.awdl.peers.peers[&src],
                    host_ifindex,
                );
            }
            RxResult::UnexpectedFormat
            | RxResult::UnexpectedType
            | RxResult::UnexpectedValue => {
                state.awdl.stats.rx_unknown += 1;
            }
            _ => {} // ignore/filter
        }
    } else if frame_type == 2 {
        // Data frame – forward payload to the host TAP interface
        match rx_data(&frame, &src, &dst, &mut state.awdl) {
            Ok(payloads) => {
                state.awdl.stats.rx_data += 1;
                for eth_frame in payloads {
                    if let Err(e) = io::host_send(&state.io, &eth_frame) {
                        log::error!("host_send failed: {e}");
                    }
                }
            }
            Err(RxResult::UnexpectedFormat)
            | Err(RxResult::UnexpectedType)
            | Err(RxResult::UnexpectedValue) => {
                state.awdl.stats.rx_unknown += 1;
            }
            Err(_) => {} // ignore/filter
        }
    } else {
        state.awdl.stats.rx_unknown += 1;
    }
}

// ─── Frame send helpers ───────────────────────────────────────────────────────

/// Serialise and inject an AWDL action frame of the given type.
pub fn awdl_send_action(state: &mut DaemonState, action_type: AwdlActionType) {
    match awdl_init_full_action_frame(&mut state.awdl, &mut state.ieee80211, action_type) {
        Ok(buf) => {
            if let Err(e) = io::wlan_send(&mut state.io, buf.data()) {
                log::error!("wlan_send action failed: {e}");
            } else {
                state.awdl.stats.tx_action += 1;
            }
        }
        Err(e) => log::error!("awdl_init_full_action_frame failed: {e:?}"),
    }
}

/// Serialise an Ethernet frame as an AWDL data frame and inject it.
pub fn awdl_send_data(
    eth_frame: &[u8],
    io_state: &mut IoState,
    awdl_state: &mut AwdlState,
    ieee80211_state: &mut Ieee80211State,
) -> bool {
    if eth_frame.len() < ETHER_LENGTH {
        return false;
    }
    let src: [u8; 6] = eth_frame[ETHER_SRC_OFFSET..ETHER_SRC_OFFSET + 6]
        .try_into()
        .unwrap();
    let dst: [u8; 6] = eth_frame[ETHER_DST_OFFSET..ETHER_DST_OFFSET + 6]
        .try_into()
        .unwrap();
    let payload = &eth_frame[ETHER_LENGTH..];

    match awdl_init_full_data_frame(&src, &dst, payload, awdl_state, ieee80211_state) {
        Ok(buf) => {
            awdl_state.stats.tx_data += 1;
            if let Err(e) = io::wlan_send(io_state, buf.data()) {
                log::error!("wlan_send data failed: {e}");
                false
            } else {
                true
            }
        }
        Err(e) => {
            log::error!("awdl_init_full_data_frame failed: {e:?}");
            false
        }
    }
}

// ─── Peer cleanup + election ──────────────────────────────────────────────────

pub fn awdl_clean_peers(state: &mut DaemonState) {
    let now = clock_time_us();
    let cutoff = now.saturating_sub(state.awdl.peers.timeout);
    let host_ifindex = state.io.host_ifindex as i32;
    peers_remove_old(&mut state.awdl.peers, cutoff, |peer| {
        awdl_neighbor_remove(peer, host_ifindex);
    });
    ElectionState::run(&mut state.awdl.election, &state.awdl.peers);
}

// ─── Channel switching ────────────────────────────────────────────────────────

pub fn awdl_switch_channel(state: &mut DaemonState) {
    let now = clock_time_us();
    let slot = state.awdl.sync.current_eaw(now) as usize % AWDL_CHANSEQ_LENGTH;
    let chan_new = state.awdl.channel.sequence[slot];
    let chan_num_new = awdl_chan_num(chan_new, state.awdl.channel.enc);
    let chan_num_old = awdl_chan_num(state.awdl.channel.current, state.awdl.channel.enc);

    if chan_num_new != 0 && chan_num_new != chan_num_old {
        log::debug!("switch channel to {} (slot {})", chan_num_new, slot);
        if !state.io.wlan_is_file {
            let _ = netutils::is_channel_available(state.io.wlan_ifindex as i32, chan_num_new as u32);
            let _ = netutils::set_channel(state.io.wlan_ifindex as i32, chan_num_new as u32);
        }
        state.awdl.channel.current = chan_new;
    }
}

// ─── Stats ────────────────────────────────────────────────────────────────────

pub fn awdl_print_stats(state: &DaemonState) {
    let s = &state.awdl.stats;
    log::info!("STATISTICS");
    log::info!(
        " TX action {}, data {}, unicast {}, multicast {}",
        s.tx_action, s.tx_data, s.tx_data_unicast, s.tx_data_multicast
    );
    log::info!(
        " RX action {}, data {}, unknown {}",
        s.rx_action, s.rx_data, s.rx_unknown
    );
}

// ─── Main event loop ──────────────────────────────────────────────────────────

/// Initialise and run the daemon event loop until a termination signal is
/// received.
///
/// This function replaces `awdl_schedule` + the libev event loop from the C
/// implementation, using tokio's time and signal facilities instead.
pub async fn run(mut state: DaemonState) {
    // Compute intervals from AWDL sync state.
    let psf_interval_us = ieee80211_tu_to_usec(state.awdl.psf_interval as u64);
    let clean_interval_us = state.awdl.peers.clean_interval;
    let aw_period_us = ieee80211_tu_to_usec(
        (state.awdl.sync.presence_mode as u64) * (state.awdl.sync.aw_period as u64),
    );

    let mut psf_interval = tokio::time::interval(Duration::from_micros(psf_interval_us));
    let mut clean_interval = tokio::time::interval(Duration::from_micros(clean_interval_us));
    let mut chan_interval = tokio::time::interval(Duration::from_micros(aw_period_us));
    let mut mif_interval = tokio::time::interval(Duration::from_micros(aw_period_us / 2));

    #[cfg(target_os = "linux")]
    let stats_signal_kind = SignalKind::user_defined1();
    #[cfg(target_os = "macos")]
    let stats_signal_kind = SignalKind::info();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let stats_signal_kind = SignalKind::user_defined1();

    let mut stats_signal = signal(stats_signal_kind)
        .expect("failed to register stats signal handler");
    let mut term_signal =
        signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut int_signal =
        signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

    log::info!("OWL daemon running");

    loop {
        tokio::select! {
            _ = psf_interval.tick() => {
                awdl_send_action(&mut state, AwdlActionType::Psf);
            }
            _ = mif_interval.tick() => {
                let chan_num = awdl_chan_num(state.awdl.channel.current, state.awdl.channel.enc);
                if chan_num > 0 {
                    awdl_send_action(&mut state, AwdlActionType::Mif);
                }
            }
            _ = chan_interval.tick() => {
                awdl_switch_channel(&mut state);
            }
            _ = clean_interval.tick() => {
                awdl_clean_peers(&mut state);
            }
            _ = stats_signal.recv() => {
                awdl_print_stats(&state);
            }
            _ = term_signal.recv() => {
                log::info!("Received SIGTERM, shutting down");
                break;
            }
            _ = int_signal.recv() => {
                log::info!("Received SIGINT, shutting down");
                break;
            }
        }

        // Poll WLAN capture (non-blocking, drain all available packets)
        poll_wlan(&mut state);

        // Poll host TAP device (non-blocking, fill TX queues)
        poll_host(&mut state);

        // Attempt pending unicast transmission
        try_send_unicast(&mut state);

        // Attempt pending multicast transmission
        try_send_multicast(&mut state);
    }

    awdl_print_stats(&state);
}

/// Drain all available packets from the pcap handle (non-blocking).
fn poll_wlan(state: &mut DaemonState) {
    // Collect all available packets into a temporary buffer first, then
    // process them. This avoids a borrow conflict between the capture handle
    // (which holds an immutable borrow on state.io) and awdl_receive_frame
    // (which requires a mutable borrow on state).
    let mut packets: Vec<Vec<u8>> = Vec::new();
    if let Some(ref mut cap) = state.io.wlan_handle {
        loop {
            match cap.next_packet() {
                Ok(packet) => packets.push(packet.data.to_vec()),
                Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => break,
                Err(e) => {
                    log::error!("pcap error: {e}");
                    break;
                }
            }
        }
    }
    for data in packets {
        awdl_receive_frame(state, &data);
    }
}

/// Read Ethernet frames from the host TAP device and enqueue them for TX.
fn poll_host(state: &mut DaemonState) {
    loop {
        // Stop filling queues if they are full.
        if state.next_unicast.is_some()
            || state.tx_queue_multicast.len() >= TX_QUEUE_MULTICAST_SIZE
        {
            break;
        }

        let mut buf = vec![0u8; ETHER_MAX_LEN];
        match io::host_recv(&state.io, &mut buf) {
            Ok(0) => break, // EWOULDBLOCK
            Ok(n) => {
                buf.truncate(n);
                if n >= ETHER_LENGTH {
                    let is_multicast = buf[ETHER_DST_OFFSET] & MULTICAST_BIT != 0;
                    if is_multicast {
                        state.tx_queue_multicast.push_back(buf);
                    } else {
                        state.next_unicast = Some(buf);
                    }
                }
            }
            Err(e) => {
                log::error!("host_recv error: {e}");
                break;
            }
        }
    }
}

/// Attempt to send the pending unicast frame if the AWDL channel is open.
fn try_send_unicast(state: &mut DaemonState) {
    if state.next_unicast.is_none() {
        return;
    }
    let now = clock_time_us();
    let frame = state.next_unicast.as_ref().unwrap();
    if frame.len() < ETHER_LENGTH {
        state.next_unicast = None;
        return;
    }
    let dst: [u8; 6] = frame[ETHER_DST_OFFSET..ETHER_DST_OFFSET + 6]
        .try_into()
        .unwrap();

    // Loopback to self?
    if dst == state.awdl.self_address {
        let frame = state.next_unicast.take().unwrap();
        let _ = io::host_send(&state.io, &frame);
        return;
    }

    // Check peer exists.
    if !state.awdl.peers.peers.contains_key(&dst) {
        log::debug!(
            "Drop frame to non-peer {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]
        );
        state.next_unicast = None;
        return;
    }

    let peer = state.awdl.peers.peers[&dst].clone();
    let in_secs = can_send_unicast_in(&state.awdl, &peer, now, AWDL_UNICAST_GUARD_TU);
    if in_secs == 0.0 {
        let frame = state.next_unicast.take().unwrap();
        if awdl_send_data(
            &frame,
            &mut state.io,
            &mut state.awdl,
            &mut state.ieee80211,
        ) {
            state.awdl.stats.tx_data_unicast += 1;
        }
    }
    // If not ready yet, leave the frame in next_unicast; the loop will retry.
}

/// Attempt to send the next pending multicast frame if the AWDL channel allows.
fn try_send_multicast(state: &mut DaemonState) {
    if state.tx_queue_multicast.is_empty() {
        return;
    }
    let now = clock_time_us();
    let in_secs = can_send_in(&state.awdl, now, AWDL_MULTICAST_GUARD_TU);
    if is_multicast_eaw(&state.awdl, now) && in_secs == 0.0 {
        if let Some(frame) = state.tx_queue_multicast.pop_front() {
            if awdl_send_data(
                &frame,
                &mut state.io,
                &mut state.awdl,
                &mut state.ieee80211,
            ) {
                state.awdl.stats.tx_data_multicast += 1;
            }
        }
    }
}

// ─── Init / free ─────────────────────────────────────────────────────────────

/// Initialise the full daemon state: network utilities, I/O, and AWDL state.
pub fn awdl_init(
    wlan: &str,
    host: &str,
    chan: awdl::channel::AwdlChan,
    dump: Option<String>,
) -> Result<DaemonState, String> {
    netutils::netutils_init().map_err(|e| format!("netutils_init: {e}"))?;

    let mut io_state = IoState::new();
    let bssid = awdl::frame::AWDL_BSSID;
    io::io_state_init(&mut io_state, wlan, host, &bssid)?;

    let hostname = netutils::get_hostname().unwrap_or_else(|_| "owl".to_string());
    let now = clock_time_us();
    let awdl_state = AwdlState::new(&hostname, io_state.if_ether_addr, chan, now);

    Ok(DaemonState::new(awdl_state, io_state, dump))
}

/// Release all resources held by the daemon state.
pub fn awdl_free(state: &mut DaemonState) {
    io::io_state_free(&mut state.io);
    netutils::netutils_cleanup();
}
