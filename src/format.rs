//! Formatting helpers shared by the apps.
//!
//! One implementation, so an amount reads the same on every platform.
//! The design system's rule applies here: amounts are never silently
//! rounded (8 decimals in BTC, or explicit sats).

/// One bitcoin, in satoshis.
pub const SATS_PER_BTC: u64 = 100_000_000;

/// Formats an amount of satoshis as a BTC string with all 8 decimals.
///
/// `format_btc(123_456) == "0.00123456"`.
pub fn format_btc(sats: u64) -> String {
    format!("{}.{:08}", sats / SATS_PER_BTC, sats % SATS_PER_BTC)
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
