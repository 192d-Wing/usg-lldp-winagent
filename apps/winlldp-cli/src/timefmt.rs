//! Time formatting without external dependencies.

use std::time::{SystemTime, UNIX_EPOCH};

/// Formats Unix seconds as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn unix(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Current time in the same format.
pub fn now_utc() -> String {
    unix(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

/// Formats a duration in seconds as `1d 02:03:04` or `02:03:04`.
pub fn duration(secs: u64) -> String {
    let d = secs / 86_400;
    let rem = secs % 86_400;
    let hms = format!("{:02}:{:02}:{:02}", rem / 3600, (rem % 3600) / 60, rem % 60);
    if d > 0 { format!("{d}d {hms}") } else { hms }
}

/// Howard Hinnant's days-to-civil algorithm (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z.saturating_add(719_468);
    let era = if z >= 0 { z } else { z.saturating_sub(146_096) } / 146_097;
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(
        365_i64
            .saturating_mul(yoe)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = (5_i64.saturating_mul(doy).saturating_add(2)) / 153;
    let d = doy
        .saturating_sub((153_i64.saturating_mul(mp).saturating_add(2)) / 5)
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let y = if m <= 2 { y.saturating_add(1) } else { y };
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::{duration, unix};

    #[test]
    fn formats_known_instants() {
        assert_eq!(unix(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(unix(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(unix(1_759_968_000), "2025-10-09 00:00:00 UTC");
        assert_eq!(unix(1_791_504_000), "2026-10-09 00:00:00 UTC");
        assert_eq!(unix(1_791_504_000 + 3661), "2026-10-09 01:01:01 UTC");
        assert_eq!(duration(59), "00:00:59");
        assert_eq!(duration(90_061), "1d 01:01:01");
    }
}
