// Frame reception (RX) - parse and handle AWDL frames

use crate::channel::{AwdlChan, ChanEncoding, AWDL_CHANSEQ_LENGTH};
use crate::election::ElectionState;
use crate::frame::{AwdlActionType, AwdlTlv, AWDL_OUI, AWDL_TYPE, IEEE80211_VENDOR_SPECIFIC};
use crate::peers::{peer_add, Peer};
use crate::state::AwdlState;
use crate::sync::SyncState;
use crate::wire::{Buf, WireError};

const AWDL_SYNC_THRESHOLD: i64 = 3;

/// Result codes for RX operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxResult {
    IgnorePeer = 6,
    IgnoreRssi = 5,
    IgnoreFailedCrc = 4,
    IgnoreNoPromisc = 3,
    IgnoreFromSelf = 2,
    Ignore = 1,
    Ok = 0,
    UnexpectedFormat = -1,
    UnexpectedType = -2,
    UnexpectedValue = -3,
}

impl From<WireError> for RxResult {
    fn from(_: WireError) -> Self {
        RxResult::UnexpectedFormat
    }
}

// --- TLV handlers ---

/// Handle a Synchronization Parameters TLV from `src`
pub fn handle_sync_params_tlv(
    src_addr: &[u8; 6],
    val: &[u8],
    sync: &mut SyncState,
    election: &ElectionState,
    now: u64,
) -> RxResult {
    if !election.is_sync_master(src_addr) {
        return RxResult::Ignore; // ignore from non-master
    }

    if val.len() < 31 {
        return RxResult::UnexpectedFormat;
    }

    let time_to_next_aw_master = u16::from_le_bytes([val[1], val[2]]);
    let aw_counter_master = u16::from_le_bytes([val[29], val[30]]);

    sync.meas_total += 1;
    let sync_err = sync.sync_error_tu(now, time_to_next_aw_master, aw_counter_master);

    if sync_err.abs() > AWDL_SYNC_THRESHOLD {
        sync.meas_err += 1;
        log::trace!(
            "Sync error {} TU ({:.02}%)",
            sync_err,
            sync.meas_err as f64 * 100.0 / sync.meas_total as f64
        );
    }
    sync.update_last(now, time_to_next_aw_master, aw_counter_master);

    RxResult::Ok
}

/// Handle a Channel Sequence TLV from `src`
pub fn handle_chanseq_tlv(
    src: &mut Peer,
    val: &[u8],
    presence_mode: u8,
) -> RxResult {
    if val.len() < 6 {
        return RxResult::UnexpectedFormat;
    }
    let count = val[0];
    if (count as usize) + 1 != AWDL_CHANSEQ_LENGTH {
        return RxResult::UnexpectedValue;
    }
    let duplicate_count = val[2];
    if duplicate_count > 0 {
        return RxResult::UnexpectedValue;
    }
    let step_count = val[3];
    if (step_count as usize) + 1 != presence_mode as usize {
        return RxResult::UnexpectedValue;
    }
    let fill_channel = u16::from_le_bytes([val[4], val[5]]);
    if fill_channel != 0xffff {
        return RxResult::UnexpectedValue;
    }
    let encoding_byte = val[1];
    let enc = match ChanEncoding::from_u8(encoding_byte) {
        Some(e) => e,
        None => return RxResult::UnexpectedValue,
    };
    let size = match crate::channel::awdl_chan_encoding_size(enc) {
        Some(s) => s,
        None => return RxResult::UnexpectedValue,
    };

    let mut list = [AwdlChan::null(); AWDL_CHANSEQ_LENGTH];
    let mut offset = 6;
    for ch in list.iter_mut() {
        if offset + size > val.len() {
            return RxResult::UnexpectedFormat;
        }
        ch.val[..size].copy_from_slice(&val[offset..offset + size]);
        offset += size;
    }

    src.sequence = list;
    RxResult::Ok
}

/// Handle an Election Parameters TLV (v1)
pub fn handle_election_params_tlv(src: &mut Peer, val: &[u8]) -> RxResult {
    if src.supports_v2 {
        return RxResult::Ignore; // ignore v1 if v2 supported
    }
    if val.len() < 20 {
        return RxResult::UnexpectedFormat;
    }
    let distance_to_master = val[3];
    let master_addr: [u8; 6] = val[5..11].try_into().unwrap_or([0; 6]);
    let master_metric = u32::from_le_bytes([val[11], val[12], val[13], val[14]]);
    let self_metric = u32::from_le_bytes([val[15], val[16], val[17], val[18]]);

    src.election.height = distance_to_master as u32;
    src.election.master_addr = master_addr;
    src.election.master_metric = master_metric;
    src.election.self_metric = self_metric;

    RxResult::Ok
}

/// Handle an Election Parameters v2 TLV
pub fn handle_election_params_v2_tlv(src: &mut Peer, val: &[u8]) -> RxResult {
    if val.len() < 44 {
        return RxResult::UnexpectedFormat;
    }
    src.supports_v2 = true;

    let master_addr: [u8; 6] = val[0..6].try_into().unwrap_or([0; 6]);
    let sync_addr: [u8; 6] = val[6..12].try_into().unwrap_or([0; 6]);
    let master_counter = u32::from_le_bytes([val[12], val[13], val[14], val[15]]);
    let height = u32::from_le_bytes([val[16], val[17], val[18], val[19]]);
    let master_metric = u32::from_le_bytes([val[20], val[21], val[22], val[23]]);
    let self_metric = u32::from_le_bytes([val[24], val[25], val[26], val[27]]);
    let self_counter = u32::from_le_bytes([val[40], val[41], val[42], val[43]]);

    src.election.master_addr = master_addr;
    src.election.sync_addr = sync_addr;
    src.election.master_counter = master_counter;
    src.election.height = height;
    src.election.master_metric = master_metric;
    src.election.self_metric = self_metric;
    src.election.self_counter = self_counter;

    RxResult::Ok
}

/// Handle an ARPA TLV (hostname)
pub fn handle_arpa_tlv(src: &mut Peer, val: &[u8]) -> RxResult {
    if val.len() < 2 {
        return RxResult::UnexpectedFormat;
    }
    let name_length = val[1] as usize;
    if val.len() < 2 + name_length {
        return RxResult::UnexpectedFormat;
    }
    let name_bytes = &val[2..2 + name_length];
    src.name = String::from_utf8_lossy(name_bytes).to_string();
    RxResult::Ok
}

/// Handle a Data Path State TLV
pub fn handle_data_path_state_tlv(src: &mut Peer, val: &[u8]) -> RxResult {
    if val.len() < 5 {
        return RxResult::UnexpectedFormat;
    }
    let flags = u16::from_le_bytes([val[0], val[1]]);

    if flags & crate::frame::AWDL_DATA_PATH_FLAG_COUNTRY_CODE != 0 && val.len() >= 5 {
        src.country_code = String::from_utf8_lossy(&val[2..4]).trim_end_matches('\0').to_string();
    }

    if flags & crate::frame::AWDL_DATA_PATH_FLAG_INFRA_ADDRESS != 0 && val.len() >= 15 {
        src.infra_addr = val[9..15].try_into().unwrap_or([0; 6]);
    }

    src.sent_mif = true;
    RxResult::Ok
}

/// Handle a Version TLV
pub fn handle_version_tlv(src: &mut Peer, val: &[u8]) -> RxResult {
    if val.len() < 2 {
        return RxResult::UnexpectedFormat;
    }
    src.version = val[0];
    src.devclass = val[1];
    RxResult::Ok
}

/// Dispatch a single TLV to the appropriate handler.
/// Takes state components separately to avoid simultaneous mutable borrows.
pub fn handle_tlv_peer(
    src: &mut Peer,
    tlv_type: u8,
    val: &[u8],
    presence_mode: u8,
) -> RxResult {
    match AwdlTlv::from_u8(tlv_type) {
        Some(AwdlTlv::ChanSeq) => handle_chanseq_tlv(src, val, presence_mode),
        Some(AwdlTlv::ElectionParameters) => handle_election_params_tlv(src, val),
        Some(AwdlTlv::ElectionParametersV2) => handle_election_params_v2_tlv(src, val),
        Some(AwdlTlv::Arpa) => handle_arpa_tlv(src, val),
        Some(AwdlTlv::DataPathState) => handle_data_path_state_tlv(src, val),
        Some(AwdlTlv::Version) => handle_version_tlv(src, val),
        Some(_) | None => {
            log::trace!("Unhandled TLV type {}", tlv_type);
            RxResult::Ignore
        }
    }
}

/// Parse and validate the AWDL action frame header
pub fn parse_action_hdr(frame: &Buf) -> RxResult {
    if frame.len() < 12 {
        return RxResult::UnexpectedFormat;
    }
    // category
    let category = match frame.read_u8(0) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    if category != IEEE80211_VENDOR_SPECIFIC {
        return RxResult::UnexpectedType;
    }
    // OUI
    let oui = match frame.read_bytes(1, 3) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    if oui != AWDL_OUI {
        return RxResult::UnexpectedType;
    }
    // type
    let awdl_type = match frame.read_u8(4) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    if awdl_type != AWDL_TYPE {
        return RxResult::UnexpectedType;
    }
    RxResult::Ok
}

/// Handle a received AWDL action frame
pub fn rx_action(
    frame: &Buf,
    rssi: i8,
    tsft: u64,
    src: &[u8; 6],
    _dst: &[u8; 6],
    state: &mut AwdlState,
) -> RxResult {
    // Filter own frames
    if src == &state.self_address {
        return RxResult::IgnoreFromSelf;
    }

    // RSSI filtering
    if state.filter_rssi && rssi < state.rssi_threshold {
        // Check grace: if already a known valid peer, apply grace
        let is_known_valid = state
            .peers
            .peers
            .get(src)
            .map(|p| p.is_valid)
            .unwrap_or(false);
        if !is_known_valid || rssi < state.rssi_threshold + state.rssi_grace {
            return RxResult::IgnoreRssi;
        }
    }

    // Parse and validate action header
    let result = parse_action_hdr(frame);
    if result != RxResult::Ok {
        return result;
    }

    // Get subtype
    let subtype = match frame.read_u8(6) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };

    let _action_type = match AwdlActionType::from_u8(subtype) {
        Some(t) => t,
        None => {
            log::debug!("Unknown AWDL action subtype {}", subtype);
            return RxResult::UnexpectedType;
        }
    };

    // Add/update peer
    let now = tsft;
    peer_add::<fn(&crate::peers::Peer)>(&mut state.peers, *src, now, None);

    // Collect TLVs from the frame first to avoid simultaneous borrows
    let mut tlvs: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut offset = 16; // sizeof(awdl_action)
    loop {
        if offset >= frame.len() {
            break;
        }
        match frame.read_tlv(offset) {
            Err(_) => break,
            Ok((tlv_type, val, next)) => {
                tlvs.push((tlv_type, val.to_vec()));
                offset = next;
            }
        }
    }

    // Pass 1: handle state-only TLVs (sync params)
    let presence_mode = state.sync.presence_mode;
    for (tlv_type, val) in &tlvs {
        if *tlv_type == AwdlTlv::SynchronizationParameters as u8 {
            handle_sync_params_tlv(src, val, &mut state.sync, &state.election, now);
        }
    }

    // Pass 2: handle peer TLVs (peer mutable borrow is now exclusive)
    if let Some(peer) = state.peers.peers.get_mut(src) {
        for (tlv_type, val) in &tlvs {
            if *tlv_type != AwdlTlv::SynchronizationParameters as u8 {
                handle_tlv_peer(peer, *tlv_type, val, presence_mode);
            }
        }
    }

    state.stats.rx_action += 1;
    RxResult::Ok
}

/// Parse the LLC/SNAP header and return the protocol ID
pub fn parse_llc_header(frame: &Buf, offset: usize) -> Option<u16> {
    if frame.len() < offset + 8 {
        return None;
    }
    let dsap = frame.read_u8(offset).ok()?;
    let ssap = frame.read_u8(offset + 1).ok()?;
    let ctrl = frame.read_u8(offset + 2).ok()?;
    if dsap != 0xaa || ssap != 0xaa || ctrl != 0x03 {
        return None;
    }
    let pid = frame.read_be16(offset + 6).ok()?;
    Some(pid)
}

/// Validate the AWDL LLC header
pub fn valid_llc_header(frame: &Buf, offset: usize) -> bool {
    match parse_llc_header(frame, offset) {
        Some(pid) => pid == crate::frame::AWDL_LLC_PROTOCOL_ID,
        None => false,
    }
}

/// Handle a received AWDL data frame.
/// Returns the decoded Ethernet frame payload(s) on success.
pub fn rx_data(
    frame: &Buf,
    src: &[u8; 6],
    dst: &[u8; 6],
    state: &mut AwdlState,
) -> Result<Vec<Vec<u8>>, RxResult> {
    // Minimum: QoS(2) + LLC(8) + AWDL data header(8)
    if frame.len() < 18 {
        return Err(RxResult::UnexpectedFormat);
    }

    // Skip QoS control field
    let llc_offset = 2;
    if !valid_llc_header(frame, llc_offset) {
        return Err(RxResult::UnexpectedFormat);
    }

    // AWDL data header at offset 10 (2 QoS + 8 LLC)
    let awdl_offset = llc_offset + 8;
    if frame.len() < awdl_offset + 8 {
        return Err(RxResult::UnexpectedFormat);
    }

    let _head = frame.read_le16(awdl_offset).map_err(|_| RxResult::UnexpectedFormat)?;
    let _seq = frame.read_le16(awdl_offset + 2).map_err(|_| RxResult::UnexpectedFormat)?;
    let ethertype = frame.read_be16(awdl_offset + 6).map_err(|_| RxResult::UnexpectedFormat)?;

    // Payload starts after AWDL data header
    let payload_offset = awdl_offset + 8;
    let payload = frame.read_bytes(payload_offset, frame.len() - payload_offset)
        .map_err(|_| RxResult::UnexpectedFormat)?
        .to_vec();

    // Re-wrap as Ethernet frame: dst(6) + src(6) + ethertype(2) + payload
    let mut eth_frame = Vec::with_capacity(14 + payload.len());
    eth_frame.extend_from_slice(dst);
    eth_frame.extend_from_slice(src);
    let et = ethertype.to_be_bytes();
    eth_frame.extend_from_slice(&et);
    eth_frame.extend_from_slice(&payload);

    state.stats.rx_data += 1;
    Ok(vec![eth_frame])
}
