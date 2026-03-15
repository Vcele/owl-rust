// Frame transmission (TX) - build AWDL action and data frames

use crate::channel::{awdl_chan_num, AWDL_CHANSEQ_LENGTH};
use crate::frame::{
    AwdlActionType, AwdlTlv, AWDL_BSSID, AWDL_DATA_HEAD, AWDL_DATA_PAD,
    AWDL_DATA_ETHERTYPE, AWDL_DNS_SHORT_LOCAL, AWDL_OUI, AWDL_SOCIAL_CHANNEL_6_BIT,
    AWDL_SOCIAL_CHANNEL_44_BIT, AWDL_SOCIAL_CHANNEL_149_BIT, AWDL_TYPE,
    IEEE80211_VENDOR_SPECIFIC,
};
use crate::ieee80211::{
    IEEE80211_FTYPE_DATA, IEEE80211_FTYPE_MGMT, IEEE80211_FCTL_FROMDS,
    IEEE80211_STYPE_ACTION, IEEE80211_STYPE_QOS_DATA,
};
use crate::state::{AwdlState, Ieee80211State, clock_time_us};
use crate::wire::{Buf, WireError};

/// Compatible AWDL version (1.0)
pub const AWDL_VERSION_COMPAT: u8 = (1 << 4) | 0; // awdl_version(1, 0)

// --- Radiotap header ---

/// Size of the radiotap header we write
pub const RADIOTAP_HEADER_LEN: usize = 8;

/// Build a minimal radiotap header
pub fn ieee80211_init_radiotap_header(buf: &mut Buf) -> Result<usize, WireError> {
    // radiotap header: it_version(1), it_pad(1), it_len(2), it_present(4)
    buf.write_u8(0, 0)?; // it_version
    buf.write_u8(1, 0)?; // it_pad
    buf.write_le16(2, RADIOTAP_HEADER_LEN as u16)?; // it_len
    buf.write_le32(4, 0)?; // it_present (no fields)
    Ok(RADIOTAP_HEADER_LEN)
}

// --- IEEE 802.11 header ---

/// Size of IEEE 802.11 header (3-address)
pub const IEEE80211_HDR_LEN: usize = 24;

/// Build an IEEE 802.11 header for AWDL
pub fn ieee80211_init_awdl_hdr(
    buf: &mut Buf,
    src: &[u8; 6],
    dst: &[u8; 6],
    state: &mut Ieee80211State,
    frame_control: u16,
) -> Result<usize, WireError> {
    let seq = state.next_sequence_number() << 4;
    buf.write_le16(0, frame_control)?;
    buf.write_le16(2, 0)?; // duration
    buf.write_ether_addr(4, dst)?; // addr1 (dst)
    buf.write_ether_addr(10, src)?; // addr2 (src)
    buf.write_ether_addr(16, &AWDL_BSSID)?; // addr3 (bssid)
    buf.write_le16(22, seq)?;
    Ok(IEEE80211_HDR_LEN)
}

/// Build an action frame IEEE 802.11 header
pub fn ieee80211_init_awdl_action_hdr(
    buf: &mut Buf,
    src: &[u8; 6],
    dst: &[u8; 6],
    state: &mut Ieee80211State,
) -> Result<usize, WireError> {
    let fc = IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION;
    ieee80211_init_awdl_hdr(buf, src, dst, state, fc)
}

/// Build a data frame IEEE 802.11 header
pub fn ieee80211_init_awdl_data_hdr(
    buf: &mut Buf,
    src: &[u8; 6],
    dst: &[u8; 6],
    state: &mut Ieee80211State,
) -> Result<usize, WireError> {
    // QoS data, from DS
    let fc = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA | IEEE80211_FCTL_FROMDS;
    ieee80211_init_awdl_hdr(buf, src, dst, state, fc)
}

// --- LLC/SNAP header ---

/// Size of the LLC/SNAP header
pub const LLC_HDR_LEN: usize = 8;

/// Build the LLC/SNAP header for AWDL
pub fn llc_init_awdl_hdr(buf: &mut Buf, offset: usize) -> Result<usize, WireError> {
    buf.write_u8(offset, 0xaa)?; // DSAP = SNAP
    buf.write_u8(offset + 1, 0xaa)?; // SSAP = SNAP
    buf.write_u8(offset + 2, 0x03)?; // control
    // OUI: 00:00:00 (Ethernet encapsulation)
    buf.write_bytes(offset + 3, &[0x00, 0x00, 0x00])?;
    buf.write_be16(offset + 6, crate::frame::AWDL_LLC_PROTOCOL_ID)?;
    Ok(LLC_HDR_LEN)
}

// --- AWDL action header ---

/// Size of the AWDL action header
pub const AWDL_ACTION_HDR_LEN: usize = 16;

/// Build the AWDL action header
pub fn awdl_init_action(buf: &mut Buf, offset: usize, action_type: AwdlActionType) -> Result<usize, WireError> {
    let now = clock_time_us() as u32;
    buf.write_u8(offset, IEEE80211_VENDOR_SPECIFIC)?; // category
    buf.write_bytes(offset + 1, &AWDL_OUI)?; // OUI
    buf.write_u8(offset + 4, AWDL_TYPE)?; // type
    buf.write_u8(offset + 5, AWDL_VERSION_COMPAT)?; // version
    buf.write_u8(offset + 6, action_type as u8)?; // subtype
    buf.write_u8(offset + 7, 0)?; // reserved
    buf.write_le32(offset + 8, now)?; // phy_tx
    buf.write_le32(offset + 12, now)?; // target_tx
    Ok(AWDL_ACTION_HDR_LEN)
}

// --- Channel sequence ---

/// Build a channel sequence block and return the number of bytes written
pub fn awdl_init_chanseq(buf: &mut Buf, offset: usize, state: &AwdlState) -> Result<usize, WireError> {
    let enc_len = crate::channel::awdl_chan_encoding_size(state.channel.enc)
        .unwrap_or(2);
    let hdr_len = 6; // awdl_chanseq struct
    buf.write_u8(offset, (AWDL_CHANSEQ_LENGTH - 1) as u8)?; // count (N-1)
    buf.write_u8(offset + 1, state.channel.enc as u8)?; // encoding
    buf.write_u8(offset + 2, 0)?; // duplicate_count
    buf.write_u8(offset + 3, 3)?; // step_count
    buf.write_le16(offset + 4, 0xffff)?; // fill_channel

    let mut pos = offset + hdr_len;
    for i in 0..AWDL_CHANSEQ_LENGTH {
        let chan = &state.channel.sequence[i];
        buf.write_bytes(pos, &chan.val[..enc_len])?;
        pos += enc_len;
    }
    Ok(pos - offset)
}

// --- TLV writers ---

fn write_tl(buf: &mut Buf, offset: usize, tlv_type: u8, length: u16) -> Result<(), WireError> {
    buf.write_u8(offset, tlv_type)?;
    buf.write_le16(offset + 1, length)?;
    Ok(())
}

/// Build the Synchronization Parameters TLV
pub fn awdl_init_sync_params_tlv(buf: &mut Buf, offset: usize, state: &AwdlState) -> Result<usize, WireError> {
    let now = clock_time_us();
    // Calculate chanseq size
    let enc_len = crate::channel::awdl_chan_encoding_size(state.channel.enc).unwrap_or(2);
    let chanseq_total = 6 + AWDL_CHANSEQ_LENGTH * enc_len;

    // Fixed part length (without chanseq): 30 bytes
    let fixed_len: u16 = 30;
    let total_len: u16 = fixed_len + chanseq_total as u16;
    write_tl(buf, offset, AwdlTlv::SynchronizationParameters as u8, total_len)?;

    let o = offset + 3;
    let current_aw_ch = awdl_chan_num(state.channel.current, state.channel.enc);
    buf.write_u8(o, current_aw_ch)?; // next_aw_channel
    let aw_period = state.sync.aw_period;
    let presence = state.sync.presence_mode;
    buf.write_le16(o + 1, state.sync.next_aw_tu(now))?; // tx_down_counter
    buf.write_u8(o + 3, 0)?; // master_channel
    buf.write_u8(o + 4, 0)?; // guard_time
    buf.write_le16(o + 5, aw_period)?; // aw_period
    buf.write_le16(o + 7, state.psf_interval)?; // af_period
    buf.write_le16(o + 9, 0x1800)?; // flags
    buf.write_le16(o + 11, aw_period)?; // aw_ext_length
    buf.write_le16(o + 13, aw_period)?; // aw_com_length
    buf.write_le16(o + 15, state.sync.next_aw_tu(now))?; // remaining_aw_length
    buf.write_u8(o + 17, presence - 1)?; // min_ext
    buf.write_u8(o + 18, presence - 1)?; // max_ext_multicast
    buf.write_u8(o + 19, presence - 1)?; // max_ext_unicast
    buf.write_u8(o + 20, presence - 1)?; // max_ext_af
    buf.write_ether_addr(o + 21, &state.election.master_addr)?; // master_addr
    buf.write_u8(o + 27, presence)?; // presence_mode
    buf.write_u8(o + 28, 0)?; // reserved
    let next_aw_seq = state.sync.current_aw(now);
    buf.write_le16(o + 29, next_aw_seq)?; // next_aw_seq; also ap_alignment but we skip it here

    // Append channel sequence
    let cs_offset = o + fixed_len as usize;
    awdl_init_chanseq(buf, cs_offset, state)?;

    Ok(3 + total_len as usize)
}

/// Build the Channel Sequence TLV
pub fn awdl_init_chanseq_tlv(buf: &mut Buf, offset: usize, state: &AwdlState) -> Result<usize, WireError> {
    let enc_len = crate::channel::awdl_chan_encoding_size(state.channel.enc).unwrap_or(2);
    let chanseq_total = 6 + AWDL_CHANSEQ_LENGTH * enc_len;
    let total_len = chanseq_total as u16 + 3; // chanseq + 3 bytes pad
    write_tl(buf, offset, AwdlTlv::ChanSeq as u8, total_len)?;
    let cs_offset = offset + 3;
    awdl_init_chanseq(buf, cs_offset, state)?;
    buf.write_bytes(cs_offset + chanseq_total, &[0x00, 0x00, 0x00])?;
    Ok(3 + total_len as usize)
}

/// Build the Election Parameters TLV (v1)
pub fn awdl_init_election_params_tlv(buf: &mut Buf, offset: usize, state: &AwdlState) -> Result<usize, WireError> {
    let len: u16 = 20;
    write_tl(buf, offset, AwdlTlv::ElectionParameters as u8, len)?;
    let o = offset + 3;
    buf.write_u8(o, 0)?; // flags
    buf.write_le16(o + 1, 0)?; // id
    buf.write_u8(o + 3, state.election.height as u8)?; // distance_to_top
    buf.write_u8(o + 4, 0)?; // unknown
    buf.write_ether_addr(o + 5, &state.election.master_addr)?; // top_master_addr
    buf.write_le32(o + 11, state.election.master_metric)?; // top_master_metric
    buf.write_le32(o + 15, state.election.self_metric)?; // self_metric
    buf.write_bytes(o + 19, &[0x00, 0x00])?; // pad
    Ok(3 + len as usize)
}

/// Build the Election Parameters v2 TLV
pub fn awdl_init_election_params_v2_tlv(buf: &mut Buf, offset: usize, state: &AwdlState) -> Result<usize, WireError> {
    let len: u16 = 44;
    write_tl(buf, offset, AwdlTlv::ElectionParametersV2 as u8, len)?;
    let o = offset + 3;
    buf.write_ether_addr(o, &state.election.master_addr)?;
    buf.write_ether_addr(o + 6, &state.election.sync_addr)?;
    buf.write_le32(o + 12, state.election.master_counter)?;
    buf.write_le32(o + 16, state.election.height)?;
    buf.write_le32(o + 20, state.election.master_metric)?;
    buf.write_le32(o + 24, state.election.self_metric)?;
    buf.write_le32(o + 28, 0)?; // unknown
    buf.write_le32(o + 32, 0)?; // reserved
    buf.write_le32(o + 36, state.election.self_counter)?;
    Ok(3 + len as usize)
}

/// Build the Service Parameters TLV
pub fn awdl_init_service_params_tlv(buf: &mut Buf, offset: usize, _state: &AwdlState) -> Result<usize, WireError> {
    let len: u16 = 9;
    write_tl(buf, offset, AwdlTlv::ServiceParameters as u8, len)?;
    let o = offset + 3;
    buf.write_bytes(o, &[0x00, 0x00, 0x00])?; // unknown
    buf.write_le16(o + 3, 0)?; // sui
    buf.write_le32(o + 5, 0)?; // bitmask
    Ok(3 + len as usize)
}

/// Build the HT Capabilities TLV
pub fn awdl_init_ht_capabilities_tlv(buf: &mut Buf, offset: usize, _state: &AwdlState) -> Result<usize, WireError> {
    let len: u16 = 9;
    write_tl(buf, offset, AwdlTlv::EnhancedDataRateCapabilities as u8, len)?;
    let o = offset + 3;
    buf.write_le16(o, 0)?; // unknown
    buf.write_le16(o + 2, 0x016e)?; // ht_capabilities
    buf.write_u8(o + 4, 0)?; // ampdu_params
    buf.write_u8(o + 5, 0xff)?; // rx_mcs
    buf.write_le16(o + 7, 0)?; // unknown2
    Ok(3 + len as usize)
}

/// Build the Data Path State TLV
pub fn awdl_init_data_path_state_tlv(buf: &mut Buf, offset: usize, state: &AwdlState) -> Result<usize, WireError> {
    let len: u16 = 16;
    write_tl(buf, offset, AwdlTlv::DataPathState as u8, len)?;
    let o = offset + 3;
    let flags: u16 = crate::frame::AWDL_DATA_PATH_FLAG_COUNTRY_CODE
        | crate::frame::AWDL_DATA_PATH_FLAG_AWDL_ADDRESS;
    buf.write_le16(o, flags)?;
    buf.write_bytes(o + 2, b"US\0")?; // country_code
    let ch_enc = state.channel.enc;
    let mut social = 0u16;
    for ch in &state.channel.sequence {
        match awdl_chan_num(*ch, ch_enc) {
            6 => social |= AWDL_SOCIAL_CHANNEL_6_BIT,
            44 => social |= AWDL_SOCIAL_CHANNEL_44_BIT,
            149 => social |= AWDL_SOCIAL_CHANNEL_149_BIT,
            _ => {}
        }
    }
    buf.write_le16(o + 5, social)?;
    buf.write_ether_addr(o + 7, &state.self_address)?;
    buf.write_le16(o + 13, 0)?; // ext_flags
    Ok(3 + len as usize)
}

/// Build the ARPA TLV (hostname advertisement)
pub fn awdl_init_arpa_tlv(buf: &mut Buf, offset: usize, state: &AwdlState) -> Result<usize, WireError> {
    let name = state.name.as_bytes();
    let name_len = name.len().min(255) as u8;
    let len: u16 = 2 + name_len as u16 + 2; // flags(1) + name_length(1) + name + suffix(2)
    write_tl(buf, offset, AwdlTlv::Arpa as u8, len)?;
    let o = offset + 3;
    buf.write_u8(o, 3)?; // flags
    buf.write_u8(o + 1, name_len)?; // name_length
    buf.write_bytes(o + 2, &name[..name_len as usize])?;
    buf.write_le16(o + 2 + name_len as usize, AWDL_DNS_SHORT_LOCAL)?; // .local suffix
    Ok(3 + len as usize)
}

/// Build the Version TLV
pub fn awdl_init_version_tlv(buf: &mut Buf, offset: usize, state: &AwdlState) -> Result<usize, WireError> {
    let len: u16 = 2;
    write_tl(buf, offset, AwdlTlv::Version as u8, len)?;
    let o = offset + 3;
    buf.write_u8(o, state.version)?;
    buf.write_u8(o + 1, state.dev_class)?;
    Ok(3 + len as usize)
}

/// Build the AWDL data header
pub fn awdl_init_data(buf: &mut Buf, offset: usize, state: &mut AwdlState) -> Result<usize, WireError> {
    let seq = state.next_sequence_number();
    buf.write_le16(offset, AWDL_DATA_HEAD)?;
    buf.write_le16(offset + 2, seq)?;
    buf.write_le16(offset + 4, AWDL_DATA_PAD)?;
    buf.write_be16(offset + 6, AWDL_DATA_ETHERTYPE)?;
    Ok(8) // sizeof(awdl_data)
}

/// Build a complete AWDL action frame
pub fn awdl_init_full_action_frame(
    state: &mut AwdlState,
    ieee: &mut Ieee80211State,
    action_type: AwdlActionType,
) -> Result<Buf, WireError> {
    // Allocate a large enough buffer
    let max_size = 2048;
    let mut buf = Buf::new(max_size);
    let mut offset = 0;

    offset += ieee80211_init_radiotap_header(&mut buf)?;
    offset += ieee80211_init_awdl_action_hdr(&mut buf, &state.self_address, &state.dst, ieee)?;
    offset += awdl_init_action(&mut buf, offset, action_type)?;

    // Add TLVs
    offset += awdl_init_sync_params_tlv(&mut buf, offset, state)?;
    offset += awdl_init_election_params_tlv(&mut buf, offset, state)?;
    offset += awdl_init_election_params_v2_tlv(&mut buf, offset, state)?;
    offset += awdl_init_chanseq_tlv(&mut buf, offset, state)?;
    offset += awdl_init_service_params_tlv(&mut buf, offset, state)?;
    offset += awdl_init_data_path_state_tlv(&mut buf, offset, state)?;
    offset += awdl_init_arpa_tlv(&mut buf, offset, state)?;
    offset += awdl_init_version_tlv(&mut buf, offset, state)?;
    offset += awdl_init_ht_capabilities_tlv(&mut buf, offset, state)?;

    buf.take(max_size - offset)?;
    Ok(buf)
}

/// Build a complete AWDL data frame wrapping an Ethernet payload
pub fn awdl_init_full_data_frame(
    src: &[u8; 6],
    dst: &[u8; 6],
    payload: &[u8],
    state: &mut AwdlState,
    ieee: &mut Ieee80211State,
) -> Result<Buf, WireError> {
    let frame_size = RADIOTAP_HEADER_LEN + IEEE80211_HDR_LEN + 2 /* QoS */ + LLC_HDR_LEN + 8 /* awdl_data */ + payload.len();
    let mut buf = Buf::new(frame_size);
    let mut offset = 0;

    offset += ieee80211_init_radiotap_header(&mut buf)?;
    offset += ieee80211_init_awdl_data_hdr(&mut buf, src, dst, ieee)?;
    // QoS control field
    buf.write_le16(offset, 0)?;
    offset += 2;
    offset += llc_init_awdl_hdr(&mut buf, offset)?;
    offset += awdl_init_data(&mut buf, offset, state)?;
    buf.write_bytes(offset, payload)?;

    Ok(buf)
}
