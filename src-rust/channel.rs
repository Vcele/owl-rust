// Channel management for AWDL

use crate::ieee80211;

pub const AWDL_CHANSEQ_LENGTH: usize = 16;

/// Channel encoding type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ChanEncoding {
    Simple = 0,
    Legacy = 1,
    #[default]
    OpClass = 3,
}

impl ChanEncoding {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ChanEncoding::Simple),
            1 => Some(ChanEncoding::Legacy),
            3 => Some(ChanEncoding::OpClass),
            _ => None,
        }
    }
}

/// An AWDL channel representation
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AwdlChan {
    pub val: [u8; 2],
}

impl AwdlChan {
    pub const fn null() -> Self {
        AwdlChan { val: [0, 0x00] }
    }

    /// Channel 6, 2.4 GHz, opclass encoding
    pub const fn opclass_6() -> Self {
        AwdlChan { val: [6, 0x51] }
    }

    /// Channel 44, 5 GHz, opclass encoding
    pub const fn opclass_44() -> Self {
        AwdlChan { val: [44, 0x80] }
    }

    /// Channel 149, 5 GHz, opclass encoding
    pub const fn opclass_149() -> Self {
        AwdlChan { val: [149, 0x80] }
    }
}

/// Get the channel number from a channel given its encoding
pub fn awdl_chan_num(chan: AwdlChan, enc: ChanEncoding) -> u8 {
    match enc {
        ChanEncoding::Simple => chan.val[0],  // simple: chan_num is first byte
        ChanEncoding::Legacy => chan.val[1],  // legacy: chan_num is second byte
        ChanEncoding::OpClass => chan.val[0], // opclass: chan_num is first byte
    }
}

/// Get the number of bytes used to encode a channel for a given encoding
pub fn awdl_chan_encoding_size(enc: ChanEncoding) -> Option<usize> {
    match enc {
        ChanEncoding::Simple => Some(1),
        ChanEncoding::Legacy | ChanEncoding::OpClass => Some(2),
    }
}

/// Channel state
#[derive(Debug, Clone)]
pub struct ChannelState {
    pub enc: ChanEncoding,
    pub sequence: [AwdlChan; AWDL_CHANSEQ_LENGTH],
    pub master: AwdlChan,
    pub current: AwdlChan,
}

impl Default for ChannelState {
    fn default() -> Self {
        ChannelState {
            enc: ChanEncoding::OpClass,
            sequence: [AwdlChan::null(); AWDL_CHANSEQ_LENGTH],
            master: AwdlChan::null(),
            current: AwdlChan::null(),
        }
    }
}

/// Initialize the default channel sequence (8 channels on 149, 8 on 6)
pub fn chanseq_init(seq: &mut [AwdlChan; AWDL_CHANSEQ_LENGTH]) {
    for (i, ch) in seq.iter_mut().enumerate() {
        *ch = if i < 8 {
            AwdlChan::opclass_149()
        } else {
            AwdlChan::opclass_6()
        };
    }
}

/// Initialize an idle channel sequence
pub fn chanseq_init_idle(seq: &mut [AwdlChan; AWDL_CHANSEQ_LENGTH]) {
    for (i, ch) in seq.iter_mut().enumerate() {
        *ch = match i {
            8 => AwdlChan::opclass_6(),
            0 | 9 | 10 => AwdlChan::opclass_149(),
            _ => AwdlChan::null(),
        };
    }
}

/// Initialize a static channel sequence (all slots set to one channel)
pub fn chanseq_init_static(seq: &mut [AwdlChan; AWDL_CHANSEQ_LENGTH], chan: AwdlChan) {
    for ch in seq.iter_mut() {
        *ch = chan;
    }
}

/// Convert IEEE 802.11 channel number to frequency in MHz
pub fn channel_to_frequency(chan: i32) -> i32 {
    ieee80211::ieee80211_channel_to_frequency(chan)
}

/// Convert frequency in MHz to IEEE 802.11 channel number
pub fn frequency_to_channel(freq: i32) -> i32 {
    ieee80211::ieee80211_frequency_to_channel(freq)
}
