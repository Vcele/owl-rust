// AWDL transmission scheduling

use crate::channel::{awdl_chan_num, AWDL_CHANSEQ_LENGTH};
use crate::ieee80211::ieee80211_tu_to_usec;
use crate::peers::Peer;
use crate::state::AwdlState;

pub const AWDL_UNICAST_GUARD_TU: u32 = 3;
pub const AWDL_MULTICAST_GUARD_TU: u32 = 16;

/// Convert microseconds to seconds
pub fn usec_to_sec(usec: u64) -> f64 {
    usec as f64 / 1_000_000.0
}

/// Convert seconds to microseconds
pub fn sec_to_usec(sec: f64) -> u64 {
    (sec * 1_000_000.0) as u64
}

/// Determine whether we are on the same non-zero channel as `peer`
pub fn same_channel_as_peer(state: &AwdlState, now: u64, peer: &Peer) -> bool {
    let own_slot =
        state.sync.current_eaw(now) as usize % AWDL_CHANSEQ_LENGTH;
    let peer_slot =
        state.sync.current_eaw(now + peer.sync_offset) as usize % AWDL_CHANSEQ_LENGTH;

    let own_chan = awdl_chan_num(state.channel.sequence[own_slot], state.channel.enc);
    let peer_chan = awdl_chan_num(peer.sequence[peer_slot], state.channel.enc);

    own_chan != 0 && own_chan == peer_chan
}

/// Determine whether we are in a multicast Extended Awake Window
pub fn is_multicast_eaw(state: &AwdlState, now: u64) -> bool {
    let slot = state.sync.current_eaw(now) as usize % AWDL_CHANSEQ_LENGTH;
    slot == 0 || slot == 10
}

/// Determine how long (in seconds) until we can send.
///
/// Returns 0 if we can send now, a positive value if we need to wait,
/// or a negative value if we just missed the window.
///
/// The guard parameter specifies how many TU before/after the slot
/// boundary we consider a no-send zone.
pub fn can_send_in(state: &AwdlState, now: u64, guard: u32) -> f64 {
    let next_aw = state.sync.next_aw_us(now);
    let guard_us = ieee80211_tu_to_usec(guard as u64);
    let eaw_us = ieee80211_tu_to_usec(64);

    if next_aw < guard_us {
        // We are at the start of a new slot (guard zone at beginning)
        -usec_to_sec(guard_us - next_aw)
    } else if eaw_us - next_aw < guard_us {
        // We are near the end of the slot (guard zone at end)
        usec_to_sec(guard_us - (eaw_us - next_aw))
    } else {
        0.0
    }
}

/// Determine how long until we can send a unicast frame to `peer`
pub fn can_send_unicast_in(state: &AwdlState, peer: &Peer, now: u64, guard: u32) -> f64 {
    let next_aw = state.sync.next_aw_us(now);
    let guard_us = ieee80211_tu_to_usec(guard as u64);
    let eaw_us = ieee80211_tu_to_usec(64);

    if !same_channel_as_peer(state, now, peer) {
        return usec_to_sec(next_aw); // try again in the next slot
    }

    if next_aw < guard_us {
        // We are at the end of a slot
        if same_channel_as_peer(state, now.saturating_add(eaw_us), peer) {
            0.0 // we are on the same channel in the next slot, ignore guard
        } else {
            -usec_to_sec(guard_us - next_aw)
        }
    } else if eaw_us - next_aw < guard_us {
        // We are at the start of a slot
        if same_channel_as_peer(state, now.saturating_sub(eaw_us), peer) {
            0.0 // we were on the same channel in the last slot, ignore guard
        } else {
            usec_to_sec(guard_us - (eaw_us - next_aw))
        }
    } else {
        0.0 // we are inside the slot, ok to send
    }
}
