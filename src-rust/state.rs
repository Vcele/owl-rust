// Complete AWDL node state

use std::time::{SystemTime, UNIX_EPOCH};

use crate::channel::{AwdlChan, ChannelState, ChanEncoding, chanseq_init_static};
use crate::election::ElectionState;
use crate::peers::PeerState;
use crate::sync::SyncState;
use crate::version::{AWDL_DEVCLASS_MACOS, awdl_version};

pub const HOST_NAME_LENGTH_MAX: usize = 64;
pub const RSSI_THRESHOLD_DEFAULT: i8 = -65;
pub const RSSI_GRACE_DEFAULT: i8 = -5;
pub const PSF_INTERVAL_MASTER_TU: u16 = 110;
pub const PSF_INTERVAL_SLAVE_TU: u16 = 440;

pub const ETHER_BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

/// Statistics counters for AWDL frames
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub tx_action: u64,
    pub tx_data: u64,
    pub tx_data_unicast: u64,
    pub tx_data_multicast: u64,
    pub rx_action: u64,
    pub rx_data: u64,
    pub rx_unknown: u64,
}

/// Complete AWDL node state
pub struct AwdlState {
    pub self_address: [u8; 6],
    pub name: String,

    pub version: u8,
    pub dev_class: u8,

    /// Sequence number for data frames
    pub sequence_number: u16,
    /// PSF interval (in TU)
    pub psf_interval: u16,
    /// Destination address for action frames
    pub dst: [u8; 6],

    pub filter_rssi: bool,
    pub rssi_threshold: i8,
    pub rssi_grace: i8,

    pub election: ElectionState,
    pub sync: SyncState,
    pub channel: ChannelState,
    pub peers: PeerState,
    pub stats: Stats,
}

impl AwdlState {
    /// Initialize the AWDL state
    pub fn new(hostname: &str, self_addr: [u8; 6], chan: AwdlChan, now: u64) -> Self {
        let mut channel = ChannelState {
            enc: ChanEncoding::OpClass,
            master: chan,
            current: AwdlChan::null(),
            ..Default::default()
        };
        chanseq_init_static(&mut channel.sequence, chan);

        AwdlState {
            self_address: self_addr,
            name: hostname.chars().take(HOST_NAME_LENGTH_MAX).collect(),
            version: awdl_version(3, 4),
            dev_class: AWDL_DEVCLASS_MACOS,
            sequence_number: 0,
            psf_interval: PSF_INTERVAL_MASTER_TU,
            dst: ETHER_BROADCAST,
            filter_rssi: true,
            rssi_threshold: RSSI_THRESHOLD_DEFAULT,
            rssi_grace: RSSI_GRACE_DEFAULT,
            election: ElectionState::new(self_addr),
            sync: SyncState::new(now),
            channel,
            peers: PeerState::new(),
            stats: Stats::default(),
        }
    }

    /// Get and increment the next sequence number for data frames
    pub fn next_sequence_number(&mut self) -> u16 {
        let seq = self.sequence_number;
        self.sequence_number = self.sequence_number.wrapping_add(1);
        seq
    }
}

/// IEEE 802.11 layer state
#[derive(Debug, Clone, Default)]
pub struct Ieee80211State {
    /// IEEE 802.11 sequence number (12-bit)
    pub sequence_number: u16,
    /// Whether to append an FCS
    pub fcs: bool,
}

impl Ieee80211State {
    pub fn new() -> Self {
        Ieee80211State {
            sequence_number: 0,
            fcs: false,
        }
    }

    /// Get and increment the next IEEE 802.11 sequence number
    pub fn next_sequence_number(&mut self) -> u16 {
        let seq = self.sequence_number;
        self.sequence_number = (self.sequence_number + 1) & 0x0fff;
        seq
    }
}

/// Get current time in microseconds since Unix epoch
pub fn clock_time_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}
