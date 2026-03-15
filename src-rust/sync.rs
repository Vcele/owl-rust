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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ieee80211::ieee80211_tu_to_usec;

    fn test_state(now: u64) -> SyncState {
        SyncState::new(now)
    }

    #[test]
    fn test_next_aw_tu() {
        let now_init: u64 = 0;
        let state = test_state(now_init);
        let eaw_period: u64 = state.presence_mode as u64 * state.aw_period as u64; // 4 * 16 = 64

        let mut now = now_init;
        for tu in 0u64..4 * eaw_period {
            while now < ieee80211_tu_to_usec(tu + 1) {
                let next = state.next_aw_tu(now);
                let expected = (eaw_period - (tu % eaw_period)) as u16;
                assert_eq!(next, expected, "at now={} (tu={})", now, tu);
                now += 1;
            }
        }
    }

    #[test]
    fn test_current_aw() {
        let now: u64 = 0;

        for &aw in &[0u16, 1337u16, 0xffffu16] {
            let mut state = test_state(now);
            state.aw_counter = aw;
            let current = state.current_aw(now);
            assert_eq!(current, aw);
        }
    }

    #[test]
    fn test_current_aw_timedelta() {
        let state = test_state(0);
        let mut tu: u64 = 0;

        for aw in 0u16..0xffff {
            while tu < (aw as u64 + 1) * state.aw_period as u64 {
                let current = state.current_aw(ieee80211_tu_to_usec(tu));
                assert_eq!(current, aw, "at tu={}", tu);
                tu += 1;
            }
        }
    }
}
