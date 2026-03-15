// Peer management for AWDL

use std::collections::HashMap;
use crate::election::ElectionState;
use crate::channel::{AwdlChan, AWDL_CHANSEQ_LENGTH, chanseq_init_static};

pub const HOST_NAME_LENGTH_MAX: usize = 64;
pub const PEERS_DEFAULT_TIMEOUT: u64 = 2_000_000; // microseconds
pub const PEERS_DEFAULT_CLEAN_INTERVAL: u64 = 1_000_000; // microseconds

/// Status codes returned by peer operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeersStatus {
    Updated,
    Ok,
    Missing,
    Internal,
}

/// A discovered AWDL peer
#[derive(Debug, Clone)]
pub struct Peer {
    pub addr: [u8; 6],
    pub last_update: u64,
    pub election: ElectionState,
    pub sequence: [AwdlChan; AWDL_CHANSEQ_LENGTH],
    pub sync_offset: u64,
    pub name: String,
    pub country_code: String,
    pub infra_addr: [u8; 6],
    pub version: u8,
    pub devclass: u8,
    pub supports_v2: bool,
    pub sent_mif: bool,
    pub is_valid: bool,
}

impl Peer {
    /// Create a new peer with the given address
    pub fn new(addr: [u8; 6]) -> Self {
        let mut sequence = [AwdlChan::null(); AWDL_CHANSEQ_LENGTH];
        chanseq_init_static(&mut sequence, AwdlChan::null());
        Peer {
            addr,
            last_update: 0,
            election: ElectionState::new(addr),
            sequence,
            sync_offset: 0,
            name: String::new(),
            country_code: String::from("NA"),
            infra_addr: [0; 6],
            version: 0,
            devclass: 0,
            supports_v2: false,
            sent_mif: false,
            is_valid: false,
        }
    }

    /// Determine if this peer has provided enough info to be considered valid
    pub fn is_valid_peer(&self) -> bool {
        self.sent_mif && self.devclass != 0 && self.version != 0
    }
}

/// The complete peer management state
pub struct PeerState {
    pub peers: HashMap<[u8; 6], Peer>,
    pub timeout: u64,
    pub clean_interval: u64,
}

impl PeerState {
    pub fn new() -> Self {
        PeerState {
            peers: HashMap::new(),
            timeout: PEERS_DEFAULT_TIMEOUT,
            clean_interval: PEERS_DEFAULT_CLEAN_INTERVAL,
        }
    }
}

impl Default for PeerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Add or update a peer. Calls `on_valid` if the peer transitions to valid.
pub fn peer_add<F>(
    state: &mut PeerState,
    addr: [u8; 6],
    now: u64,
    on_valid: Option<F>,
) -> PeersStatus
where
    F: FnOnce(&Peer),
{
    let existed = state.peers.contains_key(&addr);
    let peer = state.peers.entry(addr).or_insert_with(|| Peer::new(addr));
    peer.last_update = now;

    let was_valid = peer.is_valid;
    if !was_valid && peer.is_valid_peer() {
        peer.is_valid = true;
        log::info!("add peer {:?} ({})", peer.addr, peer.name);
        if let Some(cb) = on_valid {
            cb(peer);
        }
    }

    if existed {
        PeersStatus::Updated
    } else {
        PeersStatus::Ok
    }
}

/// Remove a peer by address. Calls `on_remove` if the peer was valid.
pub fn peer_remove<F>(
    state: &mut PeerState,
    addr: &[u8; 6],
    on_remove: Option<F>,
) -> PeersStatus
where
    F: FnOnce(&Peer),
{
    match state.peers.remove(addr) {
        None => PeersStatus::Missing,
        Some(peer) => {
            if peer.is_valid {
                log::info!("remove peer {:?} ({})", peer.addr, peer.name);
                if let Some(cb) = on_remove {
                    cb(&peer);
                }
            }
            PeersStatus::Ok
        }
    }
}

/// Get a reference to a peer by address
pub fn peer_get<'a>(state: &'a PeerState, addr: &[u8; 6]) -> Option<&'a Peer> {
    state.peers.get(addr)
}

/// Get a mutable reference to a peer by address
pub fn peer_get_mut<'a>(state: &'a mut PeerState, addr: &[u8; 6]) -> Option<&'a mut Peer> {
    state.peers.get_mut(addr)
}

/// Remove all peers whose last_update is older than `before`, calling `on_remove` for each
pub fn peers_remove_old<F>(state: &mut PeerState, before: u64, mut on_remove: F)
where
    F: FnMut(&Peer),
{
    state.peers.retain(|_, peer| {
        if peer.last_update < before {
            if peer.is_valid {
                log::info!("remove peer {:?} ({})", peer.addr, peer.name);
                on_remove(peer);
            }
            false
        } else {
            true
        }
    });
}

/// Return the number of peers
pub fn peers_length(state: &PeerState) -> usize {
    state.peers.len()
}

/// Format a peer as a string
pub fn peer_to_string(peer: &Peer) -> String {
    let name = if peer.name.is_empty() {
        "<UNNAMED>"
    } else {
        &peer.name
    };
    format!("{}: {}", name, peer.election.tree_string())
}

/// Format all peers as a multiline string (sorted for deterministic output)
pub fn peers_to_string(state: &PeerState) -> String {
    let mut entries: Vec<String> = state
        .peers
        .values()
        .map(|p| format!("{}\n", peer_to_string(p)))
        .collect();
    entries.sort();
    entries.concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(i: u8) -> [u8; 6] {
        [i; 6]
    }

    #[test]
    fn test_init() {
        let state = PeerState::new();
        assert_eq!(peers_length(&state), 0);
    }

    #[test]
    fn test_add() {
        let mut state = PeerState::new();
        let s = peer_add::<fn(&Peer)>(&mut state, addr(0), 0, None);
        assert_eq!(s, PeersStatus::Ok);
        assert_eq!(peers_length(&state), 1);
    }

    #[test]
    fn test_add_two() {
        let mut state = PeerState::new();
        assert_eq!(peer_add::<fn(&Peer)>(&mut state, addr(0), 0, None), PeersStatus::Ok);
        assert_eq!(peers_length(&state), 1);
        assert_eq!(peer_add::<fn(&Peer)>(&mut state, addr(1), 0, None), PeersStatus::Ok);
        assert_eq!(peers_length(&state), 2);
    }

    #[test]
    fn test_add_same() {
        let mut state = PeerState::new();
        assert_eq!(peer_add::<fn(&Peer)>(&mut state, addr(0), 0, None), PeersStatus::Ok);
        assert_eq!(peers_length(&state), 1);
        assert_eq!(peer_add::<fn(&Peer)>(&mut state, addr(0), 0, None), PeersStatus::Updated);
        assert_eq!(peers_length(&state), 1);
    }

    #[test]
    fn test_remove() {
        let mut state = PeerState::new();
        peer_add::<fn(&Peer)>(&mut state, addr(0), 0, None);
        let s = peer_remove::<fn(&Peer)>(&mut state, &addr(0), None);
        assert_eq!(s, PeersStatus::Ok);
        assert_eq!(peers_length(&state), 0);
    }

    #[test]
    fn test_remove_empty() {
        let mut state = PeerState::new();
        let s = peer_remove::<fn(&Peer)>(&mut state, &addr(0), None);
        assert_eq!(s, PeersStatus::Missing);
        assert_eq!(peers_length(&state), 0);
    }

    #[test]
    fn test_remove_twice() {
        let mut state = PeerState::new();
        peer_add::<fn(&Peer)>(&mut state, addr(0), 0, None);
        peer_remove::<fn(&Peer)>(&mut state, &addr(0), None);
        let s = peer_remove::<fn(&Peer)>(&mut state, &addr(0), None);
        assert_eq!(s, PeersStatus::Missing);
        assert_eq!(peers_length(&state), 0);
    }

    #[test]
    fn test_remove_timedout() {
        let mut state = PeerState::new();
        let mut now: u64 = 0;
        peer_add::<fn(&Peer)>(&mut state, addr(0), now, None);
        // Mark peer as valid directly
        state.peers.get_mut(&addr(0)).unwrap().is_valid = true;
        assert_eq!(peers_length(&state), 1);

        // cutoff = now (0): last_update(0) < 0 is false → not removed
        let mut count = 0usize;
        peers_remove_old(&mut state, now, |_| count += 1);
        assert_eq!(peers_length(&state), 1);
        assert_eq!(count, 0);

        // cutoff = now+1 (1): last_update(0) < 1 is true → removed, callback called
        now += 1;
        peers_remove_old(&mut state, now, |p| {
            count += 1;
            assert_eq!(p.addr, addr(0));
        });
        assert_eq!(peers_length(&state), 0);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_print() {
        let mut state = PeerState::new();
        peer_add::<fn(&Peer)>(&mut state, addr(0), 0, None);
        peer_add::<fn(&Peer)>(&mut state, addr(1), 0, None);
        let s = peers_to_string(&state);
        // Output is sorted, so addr(0) comes before addr(1)
        assert!(s.contains("<UNNAMED>: 0:0:0:0:0:0 (met 60, ctr 0)\n"));
        assert!(s.contains("<UNNAMED>: 1:1:1:1:1:1 (met 60, ctr 0)\n"));
        let first_pos = s.find("0:0:0:0:0:0").unwrap();
        let second_pos = s.find("1:1:1:1:1:1").unwrap();
        assert!(first_pos < second_pos);
    }
}
