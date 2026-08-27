//! BSMS descriptor records (BIP-129, round 2).
//!
//! A coordinator such as Sparrow, Nunchuk or Keystone hands every
//! participant of a multisig a small text file:
//!
//! ```text
//! BSMS 1.0
//! wsh(sortedmulti(2,[fp/48'/0'/0'/2']xpub…/**,[fp/48'/0'/0'/2']xpub…/**))
//! /0/*,/1/*
//! bc1q…
//! ```
//!
//! Line 2 is the descriptor template, where `/**` stands for the receive
//! and change branches; line 3 restricts which branches are used; line 4
//! is the first receive address, the check every participant makes.
//! Gerfaut reads the plain form only. The encrypted form (BIP-129 with a
//! token) protects the round 1 exchange between signers and is not what
//! a watch-only wallet receives; a participant exports the plain record.

use crate::error::{CoreError, CoreResult};

/// The version line every BSMS record starts with.
const HEADER: &str = "BSMS 1.0";

fn bsms_error(detail: impl Into<String>) -> CoreError {
    CoreError::InvalidInput {
        kind: "bsms",
        detail: detail.into(),
    }
}

/// True when the text is a BSMS record (any form).
pub fn is_bsms(text: &str) -> bool {
    text.trim_start().starts_with(HEADER)
}

/// Turns a plain BSMS descriptor record into a descriptor for the
/// classifier, and the first address the record promises so the caller
/// can verify the derivation.
pub fn parse_bsms(text: &str) -> CoreResult<BsmsRecord> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.first().copied() != Some(HEADER) {
        return Err(bsms_error("not a BSMS 1.0 record"));
    }
    let [_, template, restrictions, first_address, ..] = lines[..] else {
        if lines.len() == 2 && is_encrypted(lines[1]) {
            return Err(bsms_error(
                "this BSMS file is encrypted; export the plain descriptor record from the \
                 coordinator instead",
            ));
        }
        return Err(bsms_error(
            "a BSMS record needs four lines: version, descriptor, path restrictions, first \
             address",
        ));
    };
    if !template.contains('(') {
        if is_encrypted(template) {
            return Err(bsms_error(
                "this BSMS file is encrypted; export the plain descriptor record from the \
                 coordinator instead",
            ));
        }
        return Err(bsms_error("line 2 of the record is not a descriptor"));
    }

    let branches = branches(restrictions)?;
    // `/**` is BSMS shorthand for both branches; a template may also
    // spell the multipath out, or already carry a fixed path.
    let descriptor = template.replace("/**", &format!("/<{};{}>/*", branches.0, branches.1));

    Ok(BsmsRecord {
        descriptor,
        first_address: first_address.to_owned(),
    })
}

/// A plain BSMS record, ready for the classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BsmsRecord {
    /// Descriptor with both branches as a BIP-389 multipath.
    pub descriptor: String,
    /// First receive address stated by the coordinator.
    pub first_address: String,
}

/// Path restrictions: `/0/*,/1/*` (the default and the only common
/// case) or `No path restrictions`.
fn branches(restrictions: &str) -> CoreResult<(u32, u32)> {
    if restrictions.eq_ignore_ascii_case("No path restrictions") {
        return Ok((0, 1));
    }
    let mut indices = restrictions.split(',').map(|path| {
        path.trim()
            .strip_prefix('/')
            .and_then(|rest| rest.strip_suffix("/*"))
            .and_then(|index| index.parse::<u32>().ok())
    });
    match (indices.next(), indices.next(), indices.next()) {
        (Some(Some(receive)), Some(Some(change)), None) if receive != change => {
            Ok((receive, change))
        }
        _ => Err(bsms_error(format!(
            "unsupported path restrictions `{restrictions}`; expected `/0/*,/1/*`"
        ))),
    }
}

/// An encrypted record carries hex ciphertext where the descriptor
/// should be.
fn is_encrypted(line: &str) -> bool {
    line.len() >= 32 && line.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TPUB: &str = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";

    fn record(restrictions: &str, address: &str) -> String {
        format!(
            "BSMS 1.0\nwsh(sortedmulti(1,[9a6a2580/48'/1'/0'/2']{TPUB}/**,[9a6a2580/48'/1'/0'/2']{TPUB}/**))\n{restrictions}\n{address}\n"
        )
    }

    #[test]
    fn plain_record_becomes_a_multipath_descriptor() {
        let parsed = parse_bsms(&record("/0/*,/1/*", "tb1qfirst")).unwrap();
        assert_eq!(parsed.first_address, "tb1qfirst");
        assert_eq!(parsed.descriptor.matches("/<0;1>/*").count(), 2);
        assert!(!parsed.descriptor.contains("/**"));
    }

    #[test]
    fn no_path_restrictions_means_both_branches() {
        let parsed = parse_bsms(&record("No path restrictions", "tb1qfirst")).unwrap();
        assert!(parsed.descriptor.contains("/<0;1>/*"));
    }

    #[test]
    fn odd_restrictions_are_refused() {
        assert!(parse_bsms(&record("/0/*", "tb1q")).is_err());
        assert!(parse_bsms(&record("/0/*,/0/*", "tb1q")).is_err());
    }

    #[test]
    fn encrypted_records_are_named_as_such() {
        let encrypted = format!("BSMS 1.0\n{}\n", "ab".repeat(48));
        let error = parse_bsms(&encrypted).unwrap_err().to_string();
        assert!(error.contains("encrypted"), "{error}");
    }

    #[test]
    fn short_or_foreign_records_are_refused() {
        assert!(parse_bsms("BSMS 1.0\nwsh(...)\n").is_err());
        assert!(parse_bsms("BSMS 2.0\nx\ny\nz").is_err());
        assert!(!is_bsms("wpkh(tpub.../0/*)"));
        assert!(is_bsms("  BSMS 1.0\n"));
    }
}
