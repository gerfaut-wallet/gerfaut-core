//! Backups: sealing wallets and settings under a password, reading a
//! backup before anything changes, and restoring what the user picks.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::backup::{
    self, BACKUP_VERSION, BackupBackendPreview, BackupBundle, BackupOptions, BackupPayload,
    BackupPreview, BackupWallet, BackupWalletPreview, ImportChoices, ImportReport, RefusedWallet,
};
use crate::chain;
use crate::error::{CoreError, CoreResult};
use crate::input::RecognizedKind;
use crate::now_secs;
use crate::store::WalletRecord;
use crate::wallet::meta::WalletKind;

use super::{WalletManager, build_record, check_material, find_record, find_watched, fresh_meta};

impl WalletManager {
    /// Seals the chosen wallets (every wallet by default) and, on
    /// request, the settings worth carrying over, under a password. The
    /// sealed bytes come back in both transport forms: base64 for a
    /// file, `ur:bytes` frames for an animated QR.
    pub async fn export_backup(
        &self,
        options: &BackupOptions,
        password: &str,
    ) -> CoreResult<BackupBundle> {
        let payload = {
            let state = self.state.lock().await;
            let settings = &state.payload.settings;
            let chosen = match &options.wallet_ids {
                Some(ids) => {
                    for id in ids {
                        find_record(&state.payload, id)?;
                    }
                    Some(ids.iter().map(String::as_str).collect::<HashSet<_>>())
                }
                None => None,
            };
            let wallets = state
                .payload
                .wallets
                .iter()
                .filter(|record| {
                    chosen
                        .as_ref()
                        .is_none_or(|ids| ids.contains(record.meta.id.as_str()))
                })
                .map(|record| BackupWallet {
                    name: record.meta.name.clone(),
                    network: record.meta.network,
                    kind: record.meta.kind.clone(),
                    // The effective limit is the global setting.
                    gap_limit: settings.gap_limit,
                    labels: record.meta.labels.clone(),
                    created_at: record.meta.created_at,
                    live_pinned: record.meta.live_pinned,
                })
                .collect();
            BackupPayload {
                version: BACKUP_VERSION,
                created_at: now_secs(),
                wallets,
                backends: options.include_settings.then(|| settings.backends.clone()),
                electrum_certs: options
                    .include_settings
                    .then(|| settings.electrum_certs.clone()),
                gap_limit: options.include_settings.then_some(settings.gap_limit),
            }
        };
        // The key derivation is slow on purpose: not under the lock.
        let sealed = backup::seal(&payload, password)?;
        Ok(BackupBundle {
            data: data_encoding::BASE64.encode(&sealed),
            frames: backup::frames(&sealed),
            wallet_count: payload.wallets.len() as u32,
            size_bytes: sealed.len() as u32,
        })
    }

    /// Reads a backup without touching the vault: what it holds, which
    /// of its wallets this vault already watches, and what its settings
    /// would put in place, spelled out so "apply node settings" is an
    /// answer to a question the screen actually asked.
    pub async fn preview_backup(&self, source: &str, password: &str) -> CoreResult<BackupPreview> {
        let payload = backup::open(&backup::decode_source(source)?, password)?;
        let state = self.state.lock().await;
        Ok(BackupPreview {
            created_at: payload.created_at,
            has_settings: payload.has_settings(),
            // The backends a restore would put in place: the same
            // reading as the import, so an address it would drop is not
            // promised here.
            backends: payload
                .backends
                .iter()
                .flatten()
                .filter_map(|(network, config)| {
                    let config = config.clone().canonical().ok()?;
                    Some(BackupBackendPreview {
                        network: *network,
                        backend: config.label(*network),
                    })
                })
                .collect(),
            // The hosts a restore would pin: the same reading as the
            // import, so the list shows what would land and nothing
            // that would be dropped on the way.
            electrum_hosts: restorable_certs(&payload).into_keys().collect(),
            wallets: payload
                .wallets
                .iter()
                .enumerate()
                .map(|(index, wallet)| {
                    let already_watched =
                        find_watched(&state.payload, wallet.network, &wallet.kind).is_some();
                    // What a restore checks of each wallet it takes, so
                    // the screen can leave out, and say why, one it would
                    // refuse. One already watched is skipped before that:
                    // a single state, the one that happens.
                    let refused = (!already_watched)
                        .then(|| check_material(&wallet.kind, wallet.network).err())
                        .flatten()
                        .map(|error| error.to_string());
                    BackupWalletPreview {
                        index: index as u32,
                        name: wallet.name.clone(),
                        network: wallet.network,
                        kind: wallet.kind.clone(),
                        already_watched,
                        refused,
                    }
                })
                .collect(),
        })
    }

    /// Restores the chosen wallets (all by default) as new records, the
    /// way [`Self::add_wallet`] creates them, keeping their names and
    /// labels; a wallet already watched is skipped, never duplicated or
    /// overwritten. The settings the backup carries are applied only
    /// when asked: backends replace the ones present for the same
    /// networks, the certificates accepted for the servers those
    /// backends name are added but never replaced (a fingerprint that
    /// changed is exactly what pinning refuses to switch in silence),
    /// the gap limit is bounded like [`Self::set_gap_limit`]. A wallet
    /// whose material does not hold together, a change descriptor of
    /// another wallet among it, fails the restore, named, and the vault
    /// is left as it was: the preview marks such a wallet
    /// ([`BackupWalletPreview::refused`]) so it is never asked for.
    pub async fn import_backup(
        &self,
        source: &str,
        password: &str,
        choices: &ImportChoices,
    ) -> CoreResult<ImportReport> {
        let result: CoreResult<ImportReport> = async {
            let payload = backup::open(&backup::decode_source(source)?, password)?;
            let chosen: BTreeSet<usize> = match &choices.indexes {
                Some(indexes) => indexes
                    .iter()
                    .map(|&index| {
                        let index = index as usize;
                        if index < payload.wallets.len() {
                            Ok(index)
                        } else {
                            Err(CoreError::InvalidInput {
                                kind: "backup",
                                detail: format!("this backup has no wallet at index {index}"),
                            })
                        }
                    })
                    .collect::<CoreResult<_>>()?,
                None => (0..payload.wallets.len()).collect(),
            };
            let settings_applied = choices.apply_settings && payload.has_settings();

            let mut state = self.state.lock().await;
            // Restored wallets take the gap limit in force once the settings
            // are applied.
            let gap_limit = match payload.gap_limit.filter(|_| settings_applied) {
                Some(gap_limit) => gap_limit.clamp(1, 500),
                None => state.payload.settings.gap_limit,
            };

            // Everything that can fail happens before the vault changes: a
            // descriptor the engine refuses leaves nothing half-restored.
            let mut pending: Vec<(WalletRecord, Option<bdk_wallet::Wallet>)> = Vec::new();
            let mut skipped = (payload.wallets.len() - chosen.len()) as u32;
            // A restore of every wallet leaves out, and names, one it
            // cannot watch, as it skips one already watched; one asked for
            // by index fails the restore, named.
            let asked_by_index = choices.indexes.is_some();
            let mut refused = Vec::new();
            for index in chosen {
                let wallet = &payload.wallets[index];
                let watched = find_watched(&state.payload, wallet.network, &wallet.kind).is_some()
                    || pending.iter().any(|(record, _)| {
                        record.meta.network == wallet.network && record.meta.kind == wallet.kind
                    });
                if watched {
                    skipped += 1;
                    continue;
                }
                let name = wallet.name.trim();
                if name.is_empty() {
                    return Err(CoreError::InvalidInput {
                        kind: "wallet name",
                        detail: "a wallet needs a name".to_owned(),
                    });
                }
                let mut meta = fresh_meta(
                    name,
                    wallet.network,
                    wallet.kind.clone(),
                    recognized_kind(&wallet.kind),
                    gap_limit,
                );
                meta.labels = wallet.labels.clone();
                meta.live_pinned = wallet.live_pinned;
                match build_record(meta) {
                    Ok(record) => pending.push(record),
                    Err(error) if !asked_by_index => refused.push(RefusedWallet {
                        index: index as u32,
                        name: name.to_owned(),
                        reason: error.to_string(),
                    }),
                    Err(error) => return Err(refused_wallet(name, error)),
                }
            }

            // The vault changes as a whole or not at all, and the engines
            // are kept only once it has: a save that fails must not leave
            // wallets on screen that the disk never received.
            let mut added = Vec::with_capacity(pending.len());
            let mut engines = Vec::new();
            state.commit(|next| {
                if settings_applied {
                    let settings = &mut next.settings;
                    if let Some(backends) = &payload.backends {
                        // Stored the way the settings screen stores them: a
                        // backup from a vault older than that form, or one
                        // written by hand, must not put in place an address
                        // the screen would have refused. One that cannot be
                        // read is left out, and the backend of that network
                        // stays as it was.
                        settings.backends.extend(backends.iter().filter_map(
                            |(network, config)| Some((*network, config.clone().canonical().ok()?)),
                        ));
                    }
                    for (host, fingerprint) in restorable_certs(&payload) {
                        settings.electrum_certs.entry(host).or_insert(fingerprint);
                    }
                    settings.gap_limit = gap_limit;
                }
                for (record, engine) in pending {
                    if let Some(engine) = engine {
                        engines.push((record.meta.id.clone(), engine));
                    }
                    added.push(record.meta.clone());
                    next.wallets.push(record);
                }
                Ok(())
            })?;
            state.engines.extend(engines);
            Ok(ImportReport {
                added,
                skipped,
                settings_applied,
                refused,
            })
        }
        .await;
        self.live_refresh().await;
        result
    }
}

/// The certificates a restore pins, by host, as an acceptance made by
/// hand stores them. Only those of an Electrum server that a backend of
/// the same backup names: a pin is a decision about the server the
/// settings point at, and one for a host the backup's settings never
/// reach would wait in the vault, unseen, for the day that host is
/// typed in, and take its certificate as accepted. Each one also passes
/// the check of the acceptance dialog: a backup must not pin what the
/// dialog would have refused, nor a fingerprint shaped so that no real
/// certificate can ever match it and the host becomes permanently
/// unreachable.
fn restorable_certs(payload: &BackupPayload) -> BTreeMap<String, String> {
    let named: HashSet<String> = payload
        .backends
        .iter()
        .flatten()
        .filter_map(|(network, config)| {
            chain::endpoints(config, *network, &chain::TrustedCerts::new()).ok()
        })
        .flatten()
        .filter_map(|endpoint| match endpoint {
            chain::Endpoint::Electrum(target) => {
                Some(chain::electrum::certificate_key(&target.url))
            }
            chain::Endpoint::Esplora(_) => None,
        })
        .collect();
    payload
        .electrum_certs
        .iter()
        .flatten()
        .map(|(host, fingerprint)| (chain::electrum::certificate_key(host), fingerprint))
        .filter(|(host, fingerprint)| {
            named.contains(host) && chain::tls::is_fingerprint(fingerprint)
        })
        .map(|(host, fingerprint)| (host, fingerprint.to_ascii_uppercase()))
        .collect()
}

/// A wallet of the backup a restore refused, named where the error has
/// words of its own: a backup may hold many, and the error is all a
/// person who asked for it anyway sees.
fn refused_wallet(name: &str, error: CoreError) -> CoreError {
    match error {
        CoreError::Descriptor(detail) => {
            CoreError::Descriptor(format!("\"{name}\" cannot be restored: {detail}"))
        }
        CoreError::InvalidInput { kind, detail } => CoreError::InvalidInput {
            kind,
            detail: format!("\"{name}\" cannot be restored: {detail}"),
        },
        other => other,
    }
}

/// What the import screen would have recognized a restored wallet as:
/// the material says it all.
fn recognized_kind(kind: &WalletKind) -> RecognizedKind {
    match kind {
        WalletKind::Descriptors {
            internal: Some(_), ..
        } => RecognizedKind::DescriptorPair,
        WalletKind::Descriptors { .. } => RecognizedKind::Descriptor,
        WalletKind::SingleAddress { .. } => RecognizedKind::Address,
    }
}

#[cfg(test)]
mod tests;
