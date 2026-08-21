//! Formatting helpers shared by every platform.
//!
//! A single implementation so mobile, desktop, and server render amounts
//! and identifiers exactly the same way. Two hard rules from the design
//! system apply here: amounts are never silently rounded (8 decimals in
//! BTC, or explicit sats), and addresses are only ever truncated in the
//! middle, never at the ends.

/// One bitcoin, in satoshis.
pub const SATS_PER_BTC: u64 = 100_000_000;

/// Formats an amount of satoshis as a BTC string with all 8 decimals.
///
/// `format_btc(123_456) == "0.00123456"`.
pub fn format_btc(sats: u64) -> String {
    format!("{}.{:08}", sats / SATS_PER_BTC, sats % SATS_PER_BTC)
}

/// Formats a signed satoshi delta as BTC, with an explicit sign for
/// non-negative values (`+0.00010000` / `-0.00010000`).
pub fn format_btc_signed(sats: i64) -> String {
    let sign = if sats < 0 { "-" } else { "+" };
    format!("{sign}{}", format_btc(sats.unsigned_abs()))
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

/// Truncates an identifier (address, txid, descriptor) in the middle,
/// keeping `head` characters at the start and `tail` at the end.
///
/// Both ends are what a user compares to detect a substitution by
/// malware, so the ends are always preserved. Returns the input unchanged
/// when truncation would not actually shorten it.
pub fn truncate_middle(value: &str, head: usize, tail: usize) -> String {
    const ELLIPSIS: &str = "...";
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= head + tail + ELLIPSIS.len() {
        return value.to_owned();
    }
    let start: String = chars[..head].iter().collect();
    let end: String = chars[chars.len() - tail..].iter().collect();
    format!("{start}{ELLIPSIS}{end}")
}

/// Middle truncation with the design-system defaults for addresses
/// (`bc1qxy...k9fz`).
pub fn truncate_address(address: &str) -> String {
    truncate_middle(address, 6, 4)
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
    fn btc_signed() {
        assert_eq!(format_btc_signed(-123_456), "-0.00123456");
        assert_eq!(format_btc_signed(123_456), "+0.00123456");
        assert_eq!(format_btc_signed(0), "+0.00000000");
        assert_eq!(format_btc_signed(i64::MIN), "-92233720368.54775808");
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

    #[test]
    fn truncation_keeps_both_ends() {
        let address = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
        assert_eq!(truncate_address(address), "bc1qxy...0wlh");
    }

    #[test]
    fn truncation_never_lengthens() {
        assert_eq!(truncate_middle("short", 6, 4), "short");
        assert_eq!(truncate_middle("exactlength13", 6, 4), "exactlength13");
        assert_eq!(truncate_middle("", 6, 4), "");
    }
}
