// AWDL election algorithm

use crate::peers::PeerState;

pub const AWDL_ELECTION_TREE_MAX_HEIGHT: u32 = 10;
pub const AWDL_ELECTION_METRIC_INIT: u32 = 60;
pub const AWDL_ELECTION_COUNTER_INIT: u32 = 0;

/// Election state for a node (self or peer)
#[derive(Debug, Clone)]
pub struct ElectionState {
    pub master_addr: [u8; 6],
    pub sync_addr: [u8; 6],
    pub self_addr: [u8; 6],
    pub height: u32,
    pub master_metric: u32,
    pub self_metric: u32,
    pub master_counter: u32,
    pub self_counter: u32,
}

impl ElectionState {
    /// Initialize election state with the given self address
    pub fn new(self_addr: [u8; 6]) -> Self {
        let mut state = ElectionState {
            master_addr: self_addr,
            sync_addr: self_addr,
            self_addr,
            height: 0,
            master_metric: AWDL_ELECTION_METRIC_INIT,
            self_metric: AWDL_ELECTION_METRIC_INIT,
            master_counter: AWDL_ELECTION_COUNTER_INIT,
            self_counter: AWDL_ELECTION_COUNTER_INIT,
        };
        state.reset_self();
        state
    }

    /// Whether `addr` is our sync master
    pub fn is_sync_master(&self, addr: &[u8; 6]) -> bool {
        &self.sync_addr == addr
    }

    fn reset_self(&mut self) {
        self.height = 0;
        self.master_addr = self.self_addr;
        self.sync_addr = self.self_addr;
        self.master_metric = self.self_metric;
        self.master_counter = self.self_counter;
    }

    /// Run the election algorithm against the current peer set
    pub fn run(&mut self, peers: &PeerState) {
        let old_top_master = self.master_addr;
        let old_sync_master = self.sync_addr;

        self.reset_self();

        // Track the best master state we've seen (start with self)
        let mut best_master_counter = self.master_counter;
        let mut best_master_metric = self.master_metric;
        let mut best_master_addr = self.master_addr;
        let mut best_sync_addr = self.self_addr;
        let mut best_height: u32 = 0;
        let mut found_better = false;

        for peer in peers.peers.values() {
            if !peer.is_valid {
                continue; // reject: not a valid peer
            }
            let peer_state = &peer.election;
            if peer_state.height + 1 > AWDL_ELECTION_TREE_MAX_HEIGHT {
                log::debug!(
                    "Ignore peer {:?} because sync tree would get too large ({}, max {})",
                    peer_state.self_addr,
                    peer_state.height + 1,
                    AWDL_ELECTION_TREE_MAX_HEIGHT
                );
                continue; // reject: tree would get too large
            }
            if peer_state.is_sync_master(&self.self_addr) {
                continue; // reject: cycle detection
            }

            // Compare peer's master metric to current best
            let (cur_ctr, cur_met, cur_height) = if !found_better {
                (self.master_counter, self.master_metric, 0u32)
            } else {
                (best_master_counter, best_master_metric, best_height)
            };

            let cmp_ctr = peer_state.master_counter.cmp(&cur_ctr);
            let accept = match cmp_ctr {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => {
                    let cmp_met = peer_state.master_metric.cmp(&cur_met);
                    match cmp_met {
                        std::cmp::Ordering::Greater => true,
                        std::cmp::Ordering::Less => false,
                        std::cmp::Ordering::Equal => {
                            // Same metric: tie-break by height, then address
                            if peer_state.height > cur_height {
                                false // reject: would increase sync tree length
                            } else if peer_state.height == cur_height {
                                // tie-break by address (higher is better)
                                peer_state.self_addr > (if !found_better { self.self_addr } else { best_sync_addr })
                            } else {
                                true
                            }
                        }
                    }
                }
            };

            if accept {
                best_master_counter = peer_state.master_counter;
                best_master_metric = peer_state.master_metric;
                best_master_addr = peer_state.master_addr;
                best_sync_addr = peer_state.self_addr;
                best_height = peer_state.height;
                found_better = true;
            }
        }

        if found_better {
            self.master_addr = best_master_addr;
            self.sync_addr = best_sync_addr;
            self.master_metric = best_master_metric;
            self.master_counter = best_master_counter;
            self.height = best_height + 1;
        }

        if old_top_master != self.master_addr || old_sync_master != self.sync_addr {
            log::debug!("new election tree: {}", self.tree_string());
        }
    }

    /// Format the election tree as a human-readable string
    pub fn tree_string(&self) -> String {
        let mut s = format!("{}", format_addr(&self.self_addr));
        if self.height > 0 {
            s.push_str(&format!(" -> {}", format_addr(&self.sync_addr)));
        }
        if self.height > 1 {
            s.push(' ');
            for _ in 1..self.height {
                s.push('-');
            }
            s.push_str(&format!("> {}", format_addr(&self.master_addr)));
        }
        s.push_str(&format!(
            " (met {}, ctr {})",
            self.master_metric, self.master_counter
        ));
        s
    }
}

/// Format a MAC address as a colon-separated hex string
pub fn format_addr(addr: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
    )
}

/// Compare two MAC addresses (lexicographic)
pub fn compare_ether_addr(a: &[u8; 6], b: &[u8; 6]) -> std::cmp::Ordering {
    a.cmp(b)
}
