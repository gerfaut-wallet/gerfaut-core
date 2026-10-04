//! Formatting helpers shared by the apps and the core's own texts.
//!
//! One implementation, so an amount reads the same in a notification, a
//! screen and a CSV export, and a date the same in an export and on the
//! policy page. The design system's rule applies here: amounts are never
//! silently rounded (8 decimals in BTC, or explicit sats).

/// One bitcoin, in satoshis.
pub const SATS_PER_BTC: u64 = 100_000_000;

/// Formats an amount of satoshis as a BTC string with all 8 decimals.
///
/// `format_btc(123_456) == "0.00123456"`.
pub fn format_btc(sats: u64) -> String {
    format!("{}.{:08}", sats / SATS_PER_BTC, sats % SATS_PER_BTC)
}

/// A unix time as its civil date in UTC, `(year, month, day)`, by Howard
/// Hinnant's `civil_from_days`: no calendar dependency.
pub(crate) fn civil_date(unix: u64) -> (i64, u32, u32) {
    let days = i64::try_from(unix / 86_400).unwrap_or(i64::MAX / 2);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month as u32, day as u32)
}

/// The days from 1970-01-01 to a civil date in UTC, by Howard Hinnant's
/// `days_from_civil`: the inverse of [`civil_date`].
pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month = i64::from(month);
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Groups the integer digits of a numeric string by thousands using
/// a narrow no-break space, leaving any decimal part untouched.
///
/// `group_thousands("1234567.00123456") == "1 234 567.00123456"`.
pub fn group_thousands(value: &str) -> String {
    const SEPARATOR: char = '\u{202F}';
    let (int_part, rest) = match value.find('.') {
        Some(pos) => value.split_at(pos),
        None => (value, ""),
    };
    let (sign, digits) = match int_part.strip_prefix(['-', '+']) {
        Some(digits) => (&int_part[..1], digits),
        None => ("", int_part),
    };
    let mut grouped = String::with_capacity(value.len() + digits.len() / 3 + 1);
    grouped.push_str(sign);
    let offset = digits.len() % 3;
    for (i, c) in digits.chars().enumerate() {
        if i != 0 && (i + 3 - offset) % 3 == 0 {
            grouped.push(SEPARATOR);
        }
        grouped.push(c);
    }
    grouped.push_str(rest);
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_zero() {
        assert_eq!(format_btc(0), "0.00000000");
    }

    #[test]
    fn btc_all_decimals_kept() {
        assert_eq!(format_btc(1), "0.00000001");
        assert_eq!(format_btc(123_456), "0.00123456");
        assert_eq!(format_btc(SATS_PER_BTC), "1.00000000");
        assert_eq!(format_btc(2_100_000_000_000_000), "21000000.00000000");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_date(0), (1970, 1, 1));
        assert_eq!(civil_date(951_782_400), (2000, 2, 29));
        assert_eq!(civil_date(1_756_150_867), (2025, 8, 25));
        assert_eq!(civil_date(4_107_542_399), (2100, 2, 28));
        // Past any clock: a date all the same, never a panic.
        let (year, _, _) = civil_date(u64::MAX);
        assert!(year > 9_999);
    }

    #[test]
    fn days_from_civil_dates() {
        for unix in [0, 951_782_400, 1_756_150_867, 4_107_542_399] {
            let (year, month, day) = civil_date(unix);
            assert_eq!(
                days_from_civil(year, month, day),
                (unix / 86_400) as i64,
                "{unix}"
            );
        }
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    #[test]
    fn grouping() {
        assert_eq!(group_thousands("0"), "0");
        assert_eq!(group_thousands("123"), "123");
        assert_eq!(group_thousands("1234"), "1\u{202F}234");
        assert_eq!(
            group_thousands("1234567.00123456"),
            "1\u{202F}234\u{202F}567.00123456"
        );
        assert_eq!(group_thousands("-1234567"), "-1\u{202F}234\u{202F}567");
    }
}
