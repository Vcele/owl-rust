// IEEE 802.11 constants and utility functions

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;

pub const OUI_LEN: usize = 3;
pub const FCS_LEN: usize = 4;
pub const ETHER_ADDR_LEN: usize = 6;

// Frame control field masks
pub const IEEE80211_FCTL_VERS: u16 = 0x0003;
pub const IEEE80211_FCTL_FTYPE: u16 = 0x000c;
pub const IEEE80211_FCTL_STYPE: u16 = 0x00f0;
pub const IEEE80211_FCTL_TODS: u16 = 0x0100;
pub const IEEE80211_FCTL_FROMDS: u16 = 0x0200;
pub const IEEE80211_FCTL_MOREFRAGS: u16 = 0x0400;
pub const IEEE80211_FCTL_RETRY: u16 = 0x0800;
pub const IEEE80211_FCTL_PM: u16 = 0x1000;
pub const IEEE80211_FCTL_MOREDATA: u16 = 0x2000;
pub const IEEE80211_FCTL_PROTECTED: u16 = 0x4000;
pub const IEEE80211_FCTL_ORDER: u16 = 0x8000;

pub const IEEE80211_SCTL_FRAG: u16 = 0x000F;
pub const IEEE80211_SCTL_SEQ: u16 = 0xFFF0;

// Frame types
pub const IEEE80211_FTYPE_MGMT: u16 = 0x0000;
pub const IEEE80211_FTYPE_CTL: u16 = 0x0004;
pub const IEEE80211_FTYPE_DATA: u16 = 0x0008;
pub const IEEE80211_FTYPE_EXT: u16 = 0x000c;

// Management frame subtypes
pub const IEEE80211_STYPE_ASSOC_REQ: u16 = 0x0000;
pub const IEEE80211_STYPE_ASSOC_RESP: u16 = 0x0010;
pub const IEEE80211_STYPE_REASSOC_REQ: u16 = 0x0020;
pub const IEEE80211_STYPE_REASSOC_RESP: u16 = 0x0030;
pub const IEEE80211_STYPE_PROBE_REQ: u16 = 0x0040;
pub const IEEE80211_STYPE_PROBE_RESP: u16 = 0x0050;
pub const IEEE80211_STYPE_BEACON: u16 = 0x0080;
pub const IEEE80211_STYPE_ATIM: u16 = 0x0090;
pub const IEEE80211_STYPE_DISASSOC: u16 = 0x00A0;
pub const IEEE80211_STYPE_AUTH: u16 = 0x00B0;
pub const IEEE80211_STYPE_DEAUTH: u16 = 0x00C0;
pub const IEEE80211_STYPE_ACTION: u16 = 0x00D0;

// Data frame subtypes
pub const IEEE80211_STYPE_DATA: u16 = 0x0000;
pub const IEEE80211_STYPE_QOS_DATA: u16 = 0x0080;

pub const IEEE80211_QOS_CTL_LEN: usize = 2;
pub const IEEE80211_MAX_DATA_LEN: usize = 2304;
pub const IEEE80211_MAX_FRAME_LEN: usize = 2352;

/// Convert Time Units (TU) to microseconds (1 TU = 1024 us)
#[inline]
pub fn ieee80211_tu_to_usec(tu: u64) -> u64 {
    1024 * tu
}

/// Convert microseconds to Time Units (1 TU = 1024 us)
#[inline]
pub fn ieee80211_usec_to_tu(usec: u64) -> u64 {
    usec / 1024
}

#[inline]
pub fn ieee80211_radiotap_type_to_mask(t: i32) -> i32 {
    1 << t
}

#[inline]
pub fn ieee80211_radiotap_rate_to_val(rate: i32) -> i32 {
    2 * rate
}

/// Convert IEEE 802.11 channel number to frequency in MHz
/// Adapted from iw/util.c
pub fn ieee80211_channel_to_frequency(chan: i32) -> i32 {
    if chan <= 0 {
        return 0; // not supported
    }
    // 2 GHz band
    if chan == 14 {
        return 2484;
    } else if chan < 14 {
        return 2407 + chan * 5;
    }
    // 5 GHz band
    if chan < 32 {
        return 0; // not supported
    }
    if (182..=196).contains(&chan) {
        4000 + chan * 5
    } else {
        5000 + chan * 5
    }
}

/// Convert frequency in MHz to IEEE 802.11 channel number
/// From iw/util.c
pub fn ieee80211_frequency_to_channel(freq: i32) -> i32 {
    if freq == 2484 {
        14
    } else if freq < 2484 {
        (freq - 2407) / 5
    } else if freq >= 4910 && freq <= 4980 {
        (freq - 4000) / 5
    } else if freq <= 45000 {
        (freq - 5000) / 5
    } else if freq >= 58320 && freq <= 64800 {
        (freq - 56160) / 2160
    } else {
        0
    }
}
