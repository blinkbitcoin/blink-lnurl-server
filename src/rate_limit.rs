use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Fixed-window per-IP counter. In-process only: with several replicas the
/// effective budget is per replica.
pub struct PerIpRateLimiter {
    max_requests: u32,
    window: Duration,
    max_tracked_ips: usize,
    /// Only a local deployment runs without an edge to supply the trusted
    /// client-IP header; everywhere else an absent IP means no budget.
    allow_untrusted: bool,
    counters: Mutex<HashMap<IpAddr, Window>>,
}

struct Window {
    started_at: Instant,
    count: u32,
}

impl PerIpRateLimiter {
    pub fn new(
        max_requests: u32,
        window: Duration,
        max_tracked_ips: usize,
        allow_untrusted: bool,
    ) -> Self {
        Self {
            max_requests,
            window,
            max_tracked_ips,
            allow_untrusted,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` when the request is within budget.
    pub fn check(&self, ip: Option<IpAddr>) -> bool {
        let Some(ip) = ip else {
            return self.allow_untrusted;
        };
        let now = Instant::now();
        let mut counters = match self.counters.lock() {
            Ok(counters) => counters,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !counters.contains_key(&ip) && counters.len() >= self.max_tracked_ips {
            // Only expired windows may be dropped: evicting live ones would let
            // any flood reset every counter, its own included.
            counters.retain(|_, window| now.duration_since(window.started_at) < self.window);
            if counters.len() >= self.max_tracked_ips {
                // Saturation denies every NEW ip, not the flood; make that
                // state distinguishable from ordinary throttling.
                tracing::warn!(
                    tracked_ips = counters.len(),
                    "per-ip limiter table saturated; refusing untracked ips"
                );
                return false;
            }
        }

        let window = counters.entry(ip).or_insert(Window {
            started_at: now,
            count: 0,
        });
        if now.duration_since(window.started_at) >= self.window {
            window.started_at = now;
            window.count = 0;
        }
        window.count = window.count.saturating_add(1);
        window.count <= self.max_requests
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn allows_up_to_the_budget_then_rejects_per_ip() {
        let limiter = PerIpRateLimiter::new(2, Duration::from_mins(1), 1_000, false);

        assert!(limiter.check(Some(ip(1))));
        assert!(limiter.check(Some(ip(1))));
        assert!(!limiter.check(Some(ip(1))));
        assert!(limiter.check(Some(ip(2))), "budget is per IP");
    }

    #[test]
    fn window_resets_after_expiry() {
        let limiter = PerIpRateLimiter::new(1, Duration::from_millis(20), 1_000, false);

        assert!(limiter.check(Some(ip(1))));
        assert!(
            !limiter.check(Some(ip(1))),
            "the live window must still enforce the budget"
        );
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            limiter.check(Some(ip(1))),
            "an expired window must grant a fresh budget"
        );
    }

    #[test]
    fn an_absent_trusted_ip_has_no_budget() {
        let limiter = PerIpRateLimiter::new(1_000, Duration::from_mins(1), 1_000, false);

        assert!(!limiter.check(None));
    }

    #[test]
    fn an_absent_trusted_ip_is_allowed_only_where_no_edge_supplies_one() {
        let limiter = PerIpRateLimiter::new(1_000, Duration::from_mins(1), 1_000, true);

        assert!(limiter.check(None));
    }

    #[test]
    fn a_full_table_rejects_new_ips_instead_of_clearing_live_windows() {
        let limiter = PerIpRateLimiter::new(1, Duration::from_mins(1), 2, false);

        assert!(limiter.check(Some(ip(1))));
        assert!(limiter.check(Some(ip(2))));
        assert!(
            !limiter.check(Some(ip(3))),
            "a full table must refuse a new IP rather than make room"
        );
        assert!(
            !limiter.check(Some(ip(1))),
            "the flood must not have reset an existing window"
        );
    }

    #[test]
    fn tracked_ips_stay_bounded() {
        let limiter = PerIpRateLimiter::new(10, Duration::from_mins(1), 4, false);

        for last in 0..=20 {
            limiter.check(Some(ip(last)));
        }

        assert!(limiter.counters.lock().unwrap().len() <= 4);
    }
}
