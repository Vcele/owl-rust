// AWDL synchronization state and timing

use crate::ieee80211::{ieee80211_tu_to_usec, ieee80211_usec_to_tu};

/// Synchronization state for AWDL timing
#[derive(Debug, Clone)]
pub struct SyncState {
    pub aw_counter: u16,
    pub last_update: u64, // in microseconds
    pub aw_period: u16,   // in TU
    pub presence_mode: u8,

    // Statistics
    pub meas_err: u64,
    pub meas_total: u64,
}

impl SyncState {
    /// Initialize sync state at the given time (in microseconds)
    pub fn new(now: u64) -> Self {
        SyncState {
            aw_counter: 0,
            last_update: now,
            aw_period: 16,
            presence_mode: 4,
            meas_err: 0,
            meas_total: 0,
        }
    }

    /// Time in TU until the next Awake Window
    pub fn next_aw_tu(&self, now_usec: u64) -> u16 {
        let eaw_period = self.presence_mode as u64 * self.aw_period as u64;
        let time_since = ieee80211_usec_to_tu(now_usec.saturating_sub(self.last_update));
        let next_aw_tu = eaw_period - (time_since % eaw_period);
        next_aw_tu as u16
    }

    /// Time in microseconds until the next Awake Window
    pub fn next_aw_us(&self, now_usec: u64) -> u64 {
        let eaw_period = ieee80211_tu_to_usec(self.presence_mode as u64 * self.aw_period as u64);
        let time_since = now_usec.saturating_sub(self.last_update);
        eaw_period - (time_since % eaw_period)
    }

    /// Current Awake Window number
    pub fn current_aw(&self, now_usec: u64) -> u16 {
        let eaw_period = self.presence_mode as u64 * self.aw_period as u64;
        let time_since = ieee80211_usec_to_tu(now_usec.saturating_sub(self.last_update));
        let current_aw = self.aw_counter as u64
            + (time_since % eaw_period) / self.aw_period as u64
            + self.presence_mode as u64 * (time_since / eaw_period);
        current_aw as u16
    }

    /// Current Extended Awake Window number
    pub fn current_eaw(&self, now_usec: u64) -> u16 {
        self.current_aw(now_usec) / self.presence_mode as u16
    }

    /// Calculate synchronization error in TU given a peer's announcement
    pub fn sync_error_tu(
        &self,
        now_usec: u64,
        time_to_next_aw: u16,
        aw_counter: u16,
    ) -> i64 {
        let expected_eaw = (aw_counter as i64 / self.presence_mode as i64
            - self.current_eaw(now_usec) as i64)
            * self.presence_mode as i64
            * self.aw_period as i64;
        let timing_err = time_to_next_aw as i64 - self.next_aw_tu(now_usec) as i64;
        expected_eaw - timing_err
    }

    /// Update sync state based on a received sync parameters TLV
    pub fn update_last(&mut self, now_usec: u64, time_to_next_aw: u16, aw_counter: u16) {
        let eaw_period = self.presence_mode as u64 * self.aw_period as u64;
        self.last_update =
            now_usec - ieee80211_tu_to_usec(eaw_period - time_to_next_aw as u64);
        self.aw_counter = aw_counter & 0xfffc; // mask last two bits
    }
}
