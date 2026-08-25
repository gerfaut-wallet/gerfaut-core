//! Transaction export, shared by the apps.
//!
//! Plain CSV built from the same snapshots the screens read: what you
//! see is what you export. Everything happens locally; nothing leaves
//! the machine.

use serde::{Deserialize, Serialize};

use crate::wallet::snapshot::{TxStatus, TxSummary};

/// Keep only one direction of transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportDirection {
    Incoming,
    Outgoing,
}

/// Filters for a transaction export. Empty options export everything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOptions {
    /// Unix seconds, inclusive lower bound on the confirmation time.
    #[serde(default)]
    pub from: Option<u64>,
    /// Unix seconds, inclusive upper bound on the confirmation time.
    #[serde(default)]
    pub to: Option<u64>,
    #[serde(default)]
    pub direction: Option<ExportDirection>,
    /// Pending transactions have no date: they only pass when no date
    /// bound is set.
    #[serde(default = "default_true")]
    pub include_pending: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions {
            from: None,
            to: None,
            direction: None,
            // The serde default and the Rust default must agree.
            include_pending: true,
        }
    }
}

/// A built export, ready to write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub csv: String,
    pub rows: u32,
}

const HEADER: &str =
    "txid,date_utc,block_height,confirmations,direction,amount_sats,amount_btc,fee_sats";

/// Builds the CSV for one wallet's transactions, oldest row first.
pub fn transactions_csv(txs: &[TxSummary], options: &ExportOptions) -> ExportResult {
    let mut rows: Vec<&TxSummary> = txs.iter().filter(|tx| passes(tx, options)).collect();
    rows.sort_by_key(|tx| match tx.status {
        TxStatus::Confirmed {
            timestamp, height, ..
        } => (timestamp.unwrap_or(u64::MAX), height, 0u8),
        // Pending rows close the file: they have no date yet.
        TxStatus::Pending => (u64::MAX, u32::MAX, 1),
    });

    let mut csv = String::with_capacity(64 + rows.len() * 120);
    csv.push_str(HEADER);
    csv.push('\n');
    for tx in &rows {
        let (date, height) = match tx.status {
            TxStatus::Confirmed {
                height, timestamp, ..
            } => (
                timestamp.map(format_utc).unwrap_or_default(),
                height.to_string(),
            ),
            TxStatus::Pending => (String::new(), String::new()),
        };
        let direction = if tx.net_sats >= 0 { "in" } else { "out" };
        let fee = tx.fee_sats.map(|fee| fee.to_string()).unwrap_or_default();
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            tx.txid,
            date,
            height,
            tx.confirmations,
            direction,
            tx.net_sats,
            format_btc_signed_plain(tx.net_sats),
            fee,
        ));
    }
    ExportResult {
        csv,
        rows: rows.len() as u32,
    }
}

fn passes(tx: &TxSummary, options: &ExportOptions) -> bool {
    match options.direction {
        Some(ExportDirection::Incoming) if tx.net_sats < 0 => return false,
        Some(ExportDirection::Outgoing) if tx.net_sats >= 0 => return false,
        _ => {}
    }
    match tx.status {
        TxStatus::Confirmed { timestamp, .. } => {
            // Undated confirmations (older watched-address syncs) only
            // pass an unbounded export, like pending rows.
            let Some(at) = timestamp else {
                return options.from.is_none() && options.to.is_none();
            };
            options.from.is_none_or(|from| at >= from) && options.to.is_none_or(|to| at <= to)
        }
        TxStatus::Pending => {
            options.include_pending && options.from.is_none() && options.to.is_none()
        }
    }
}

/// `-123` sats -> `-0.00000123`, plain 8 decimals, no unit, no grouping.
fn format_btc_signed_plain(sats: i64) -> String {
    let sign = if sats < 0 { "-" } else { "" };
    let abs = sats.unsigned_abs();
    format!("{sign}{}.{:08}", abs / 100_000_000, abs % 100_000_000)
}

/// Unix seconds -> `2026-08-25 19:41:07` UTC, no external dependency
/// (days-to-civil per Howard Hinnant's algorithm).
fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3_600, (rem / 60) % 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(net: i64, timestamp: Option<u64>, fee: Option<u64>) -> TxSummary {
        TxSummary {
            txid: format!("tx-{net}-{}", timestamp.unwrap_or(0)),
            net_sats: net,
            fee_sats: fee,
            status: match timestamp {
                Some(timestamp) => TxStatus::Confirmed {
                    height: 100,
                    timestamp: Some(timestamp),
                },
                None => TxStatus::Pending,
            },
            confirmations: if timestamp.is_some() { 3 } else { 0 },
        }
    }

    #[test]
    fn rows_are_oldest_first_with_a_header() {
        let result = transactions_csv(
            &[tx(-30, Some(2_000), Some(10)), tx(100, Some(1_000), None)],
            &ExportOptions::default(),
        );
        assert_eq!(result.rows, 2);
        let lines: Vec<&str> = result.csv.lines().collect();
        assert_eq!(lines[0], HEADER);
        assert!(lines[1].starts_with("tx-100-1000,1970-01-01 00:16:40,100,3,in,100,0.00000100,"));
        assert!(lines[2].contains(",out,-30,-0.00000030,10"));
    }

    #[test]
    fn filters_apply() {
        let txs = [
            tx(100, Some(1_000), None),
            tx(-30, Some(2_000), None),
            tx(50, None, None),
        ];
        let incoming = transactions_csv(
            &txs,
            &ExportOptions {
                direction: Some(ExportDirection::Incoming),
                ..Default::default()
            },
        );
        assert_eq!(incoming.rows, 2, "incoming keeps the pending receive");

        let bounded = transactions_csv(
            &txs,
            &ExportOptions {
                from: Some(1_500),
                ..Default::default()
            },
        );
        // The date bound drops the earlier tx and the undated pending.
        assert_eq!(bounded.rows, 1);

        let settled = transactions_csv(
            &txs,
            &ExportOptions {
                include_pending: false,
                ..Default::default()
            },
        );
        assert_eq!(settled.rows, 2);
    }

    #[test]
    fn utc_dates_are_exact() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00");
        assert_eq!(format_utc(1_756_150_867), "2025-08-25 19:41:07");
        assert_eq!(format_utc(951_827_696), "2000-02-29 12:34:56");
    }

    #[test]
    fn amounts_render_with_eight_plain_decimals() {
        assert_eq!(format_btc_signed_plain(150_000), "0.00150000");
        assert_eq!(format_btc_signed_plain(-1), "-0.00000001");
        assert_eq!(format_btc_signed_plain(250_000_000_000), "2500.00000000");
    }
}
