// AWDL frame definitions and TLV types

use crate::ieee80211::ETH_P_IPV6;

/// AWDL protocol constants
pub const AWDL_LLC_PROTOCOL_ID: u16 = 0x0800;
pub const AWDL_OUI: [u8; 3] = [0x00, 0x17, 0xf2];
pub const AWDL_BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];
pub const IEEE80211_VENDOR_SPECIFIC: u8 = 127;
pub const AWDL_TYPE: u8 = 8;

/// AWDL data frame header constants
pub const AWDL_DATA_HEAD: u16 = 0x0403;
pub const AWDL_DATA_PAD: u16 = 0x0000;

/// AWDL data frame ethertype (IPv6)
pub const AWDL_DATA_ETHERTYPE: u16 = ETH_P_IPV6;

/// Social channel bit flags
pub const AWDL_SOCIAL_CHANNEL_6_BIT: u16 = 0x0001;
pub const AWDL_SOCIAL_CHANNEL_44_BIT: u16 = 0x0002;
pub const AWDL_SOCIAL_CHANNEL_149_BIT: u16 = 0x0004;

/// DNS local suffix
pub const AWDL_DNS_SHORT_LOCAL: u16 = 0xc00c;

/// AWDL action frame subtypes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AwdlActionType {
    /// Periodic Synchronization Frame
    Psf = 0,
    /// Management Information Frame
    Mif = 3,
}

impl AwdlActionType {
    pub fn as_str(self) -> &'static str {
        match self {
            AwdlActionType::Psf => "PSF",
            AwdlActionType::Mif => "MIF",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(AwdlActionType::Psf),
            3 => Some(AwdlActionType::Mif),
            _ => None,
        }
    }
}

/// AWDL TLV type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AwdlTlv {
    SsthRequest = 0,
    ServiceRequest = 1,
    ServiceResponse = 2,
    SynchronizationParameters = 4,
    ElectionParameters = 5,
    ServiceParameters = 6,
    EnhancedDataRateCapabilities = 7,
    EnhancedDataRateOperation = 8,
    Infra = 9,
    Invite = 10,
    DbgString = 11,
    DataPathState = 12,
    EncapsulatedIp = 13,
    DatapathDebugPacketLive = 14,
    DatapathDebugAfLive = 15,
    Arpa = 16,
    Ieee80211Container = 17,
    ChanSeq = 18,
    SyncTree = 20,
    Version = 21,
    BloomFilter = 22,
    NanSync = 23,
    ElectionParametersV2 = 24,
}

impl AwdlTlv {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(AwdlTlv::SsthRequest),
            1 => Some(AwdlTlv::ServiceRequest),
            2 => Some(AwdlTlv::ServiceResponse),
            4 => Some(AwdlTlv::SynchronizationParameters),
            5 => Some(AwdlTlv::ElectionParameters),
            6 => Some(AwdlTlv::ServiceParameters),
            7 => Some(AwdlTlv::EnhancedDataRateCapabilities),
            8 => Some(AwdlTlv::EnhancedDataRateOperation),
            9 => Some(AwdlTlv::Infra),
            10 => Some(AwdlTlv::Invite),
            11 => Some(AwdlTlv::DbgString),
            12 => Some(AwdlTlv::DataPathState),
            13 => Some(AwdlTlv::EncapsulatedIp),
            14 => Some(AwdlTlv::DatapathDebugPacketLive),
            15 => Some(AwdlTlv::DatapathDebugAfLive),
            16 => Some(AwdlTlv::Arpa),
            17 => Some(AwdlTlv::Ieee80211Container),
            18 => Some(AwdlTlv::ChanSeq),
            20 => Some(AwdlTlv::SyncTree),
            21 => Some(AwdlTlv::Version),
            22 => Some(AwdlTlv::BloomFilter),
            23 => Some(AwdlTlv::NanSync),
            24 => Some(AwdlTlv::ElectionParametersV2),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AwdlTlv::SsthRequest => "SSTH Request",
            AwdlTlv::ServiceRequest => "Service Request",
            AwdlTlv::ServiceResponse => "Service Response",
            AwdlTlv::SynchronizationParameters => "Synchronization Parameters",
            AwdlTlv::ElectionParameters => "Election Parameters",
            AwdlTlv::ServiceParameters => "Service Parameters",
            AwdlTlv::EnhancedDataRateCapabilities => "HT Capabilities",
            AwdlTlv::EnhancedDataRateOperation => "HT Operation",
            AwdlTlv::Infra => "Infra",
            AwdlTlv::Invite => "Invite",
            AwdlTlv::DbgString => "Debug String",
            AwdlTlv::DataPathState => "Data Path State",
            AwdlTlv::EncapsulatedIp => "Encapsulated IP",
            AwdlTlv::DatapathDebugPacketLive => "Datapath Debug Packet Live",
            AwdlTlv::DatapathDebugAfLive => "Datapath Debug AF Live",
            AwdlTlv::Arpa => "Arpa",
            AwdlTlv::Ieee80211Container => "VHT Capabilities",
            AwdlTlv::ChanSeq => "Channel Sequence",
            AwdlTlv::SyncTree => "Synchronization Tree",
            AwdlTlv::Version => "Version",
            AwdlTlv::BloomFilter => "Bloom Filter",
            AwdlTlv::NanSync => "NAN Sync",
            AwdlTlv::ElectionParametersV2 => "Election Parameters v2",
        }
    }
}

pub fn awdl_tlv_as_str(type_val: u8) -> &'static str {
    match AwdlTlv::from_u8(type_val) {
        Some(t) => t.as_str(),
        None => "Unknown",
    }
}

pub fn awdl_frame_as_str(type_val: u8) -> &'static str {
    match AwdlActionType::from_u8(type_val) {
        Some(t) => t.as_str(),
        None => "Unknown",
    }
}

/// Data path state TLV flags
pub const AWDL_DATA_PATH_FLAG_COUNTRY_CODE: u16 = 0x0100;
pub const AWDL_DATA_PATH_FLAG_SOCIAL_CHANNEL_MAP: u16 = 0x0200;
pub const AWDL_DATA_PATH_FLAG_INFRA_INFO: u16 = 0x0001;
pub const AWDL_DATA_PATH_FLAG_INFRA_ADDRESS: u16 = 0x0002;
pub const AWDL_DATA_PATH_FLAG_AWDL_ADDRESS: u16 = 0x0004;
pub const AWDL_DATA_PATH_FLAG_UMI: u16 = 0x0010;
