//! `sesame_bff_store_seconds{op}`: how long each session-store call took as the request saw it (queueing for an I/O
//! thread included), and `sesame_bff_store_errors_total{op}`. Lock-free; rendered in Prometheus text by
//! [`render_prometheus`] for the service's `/metrics`.
//!
//! Every call is also recorded in the shared `op_duration_seconds{component="sesame.bff_store", op, outcome}`
//! (microscaler-timing, same buckets), which a BRRTRouter host renders on its own and the generic operation-latency
//! dashboard reads. `sesame_bff_store_seconds` stays for now so existing panels keep working; it is to be removed once
//! they read the shared family.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Bucket bounds in seconds.
const BUCKETS: [f64; 11] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
];

/// The store operations, in the order they are rendered.
pub(crate) const OPS: [&str; 10] = [
    "put_preauth",
    "take_preauth",
    "put_session",
    "get_session",
    "delete_session",
    "index_session",
    "unindex_session",
    "indexed_sessions",
    "try_lock",
    "unlock",
];

struct Hist {
    buckets: [AtomicU64; BUCKETS.len()],
    count: AtomicU64,
    sum_micros: AtomicU64,
    errors: AtomicU64,
}

impl Hist {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; BUCKETS.len()],
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

static HISTS: [Hist; OPS.len()] = [const { Hist::new() }; OPS.len()];

/// The same operations in `op_duration_seconds`, in [`OPS`] order.
static SITES: [microscaler_timing::Site; OPS.len()] = [
    microscaler_timing::Site::new("sesame.bff_store", "put_preauth"),
    microscaler_timing::Site::new("sesame.bff_store", "take_preauth"),
    microscaler_timing::Site::new("sesame.bff_store", "put_session"),
    microscaler_timing::Site::new("sesame.bff_store", "get_session"),
    microscaler_timing::Site::new("sesame.bff_store", "delete_session"),
    microscaler_timing::Site::new("sesame.bff_store", "index_session"),
    microscaler_timing::Site::new("sesame.bff_store", "unindex_session"),
    microscaler_timing::Site::new("sesame.bff_store", "indexed_sessions"),
    microscaler_timing::Site::new("sesame.bff_store", "try_lock"),
    microscaler_timing::Site::new("sesame.bff_store", "unlock"),
];

/// Record one store call. Unknown `op` names are ignored. Only the Redis store times its calls.
#[cfg_attr(not(feature = "redis-store"), allow(dead_code))]
pub(crate) fn observe(op: &str, took: Duration, ok: bool) {
    let Some(i) = OPS.iter().position(|o| *o == op) else {
        return;
    };
    SITES[i].record(
        if ok {
            microscaler_timing::Outcome::Ok
        } else {
            microscaler_timing::Outcome::Err
        },
        took,
    );
    let h = &HISTS[i];
    let secs = took.as_secs_f64();
    for (b, bound) in h.buckets.iter().zip(BUCKETS) {
        if secs <= bound {
            b.fetch_add(1, Ordering::Relaxed);
        }
    }
    h.count.fetch_add(1, Ordering::Relaxed);
    h.sum_micros.fetch_add(
        u64::try_from(took.as_micros()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    if !ok {
        h.errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Append the store metrics in Prometheus text format. Operations never called are left out.
pub fn render_prometheus(out: &mut String) {
    out.push_str("# HELP sesame_bff_store_seconds BFF session-store calls, as the request saw them, by operation\n");
    out.push_str("# TYPE sesame_bff_store_seconds histogram\n");
    for (op, h) in OPS.iter().zip(&HISTS) {
        let count = h.count.load(Ordering::Relaxed);
        if count == 0 {
            continue;
        }
        for (b, bound) in h.buckets.iter().zip(BUCKETS) {
            let _ = writeln!(
                out,
                "sesame_bff_store_seconds_bucket{{op=\"{op}\",le=\"{bound}\"}} {}",
                b.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            out,
            "sesame_bff_store_seconds_bucket{{op=\"{op}\",le=\"+Inf\"}} {count}"
        );
        let sum = h.sum_micros.load(Ordering::Relaxed) as f64 / 1e6;
        let _ = writeln!(out, "sesame_bff_store_seconds_sum{{op=\"{op}\"}} {sum}");
        let _ = writeln!(out, "sesame_bff_store_seconds_count{{op=\"{op}\"}} {count}");
    }
    out.push_str(
        "# HELP sesame_bff_store_errors_total BFF session-store calls that failed, by operation\n",
    );
    out.push_str("# TYPE sesame_bff_store_errors_total counter\n");
    for (op, h) in OPS.iter().zip(&HISTS) {
        if h.count.load(Ordering::Relaxed) == 0 {
            continue;
        }
        let _ = writeln!(
            out,
            "sesame_bff_store_errors_total{{op=\"{op}\"}} {}",
            h.errors.load(Ordering::Relaxed)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_cumulative_histogram_per_operation() {
        observe("indexed_sessions", Duration::from_millis(3), true);
        observe("indexed_sessions", Duration::from_millis(300), false);
        observe("not-an-op", Duration::from_millis(1), true);
        let mut out = String::new();
        render_prometheus(&mut out);
        assert!(out
            .contains("sesame_bff_store_seconds_bucket{op=\"indexed_sessions\",le=\"0.005\"} 1\n"));
        assert!(
            out.contains("sesame_bff_store_seconds_bucket{op=\"indexed_sessions\",le=\"0.5\"} 2\n")
        );
        assert!(out.contains("sesame_bff_store_seconds_count{op=\"indexed_sessions\"} 2\n"));
        assert!(out.contains("sesame_bff_store_errors_total{op=\"indexed_sessions\"} 1\n"));
        assert!(!out.contains("not-an-op"));
    }

    #[test]
    fn store_calls_also_land_in_op_duration_seconds() {
        observe("try_lock", Duration::from_millis(2), true);
        observe("try_lock", Duration::from_millis(2), false);
        let rows: Vec<_> = microscaler_timing::snapshot()
            .into_iter()
            .filter(|r| r.component == "sesame.bff_store" && r.op == "try_lock")
            .collect();
        let count = |o| {
            rows.iter()
                .filter(|r| r.outcome == o)
                .map(|r| r.count())
                .sum::<u64>()
        };
        assert!(count(microscaler_timing::Outcome::Ok) >= 1);
        assert!(count(microscaler_timing::Outcome::Err) >= 1);
        for (site, op) in SITES.iter().zip(OPS) {
            assert_eq!(site.op(), op);
        }
    }
}
