//! Backups: sealing wallets and settings under a password, reading a
//! backup before anything changes, and restoring what the user picks.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::backup::{
    self, BACKUP_VERSION, BackupBackendPreview, BackupBundle, BackupOptions, BackupPayload,
    BackupPreview, BackupWallet, BackupWalletPreview, ImportChoices, ImportReport, RefusedWallet,
};
use crate::chain::{self, BackendConfig};
use crate::error::{CoreError, CoreResult};
use crate::input::RecognizedKind;
use crate::network::Network;
use crate::now_secs;
use crate::store::{Settings, VaultPayload, WalletRecord};
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
    /// answer to a question the screen actually asked. All of it is read
    /// off [`plan_restore`], the plan [`Self::import_backup`] carries out:
    /// what the preview promises is what a restore of every wallet does.
    pub async fn preview_backup(&self, source: &str, password: &str) -> CoreResult<BackupPreview> {
        let payload = backup::open(&backup::decode_source(source)?, password)?;
        let state = self.state.lock().await;
        let plan = plan_restore(&state.payload, &payload, 0..payload.wallets.len());
        Ok(BackupPreview {
            created_at: payload.created_at,
            has_settings: payload.has_settings(),
            backends: plan
                .backends
                .iter()
                .map(|(network, config)| BackupBackendPreview {
                    network: *network,
                    backend: config.label(*network),
                })
                .collect(),
            electrum_hosts: plan.certs.into_keys().collect(),
            wallets: plan
                .wallets
                .into_iter()
                .map(|(index, fate)| {
                    let wallet = &payload.wallets[index];
                    BackupWalletPreview {
                        index: index as u32,
                        name: wallet.name.clone(),
                        network: wallet.network,
                        kind: wallet.kind.clone(),
                        already_watched: matches!(fate, Fate::Watched),
                        refused: match fate {
                            Fate::Refused(error) => Some(error.to_string()),
                            Fate::Watched | Fate::Restored => None,
                        },
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
    /// networks, the certificates accepted for the servers in service
    /// afterwards are added but never replaced (a fingerprint that
    /// changed is exactly what pinning refuses to switch in silence),
    /// the gap limit is bounded like [`Self::set_gap_limit`]. What is
    /// restored and what is pinned is decided by [`plan_restore`], the
    /// plan the preview shows. A wallet whose material does not hold
    /// together, a change descriptor of another wallet among it, fails
    /// the restore, named, and the vault is left as it was: the preview
    /// marks such a wallet ([`BackupWalletPreview::refused`]) so it is
    /// never asked for.
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

            let plan = plan_restore(&state.payload, &payload, chosen.iter().copied());

            // Everything that can fail happens before the vault changes: a
            // descriptor the engine refuses leaves nothing half-restored.
            let mut pending: Vec<(WalletRecord, Option<bdk_wallet::Wallet>)> = Vec::new();
            let mut skipped = (payload.wallets.len() - chosen.len()) as u32;
            // A restore of every wallet leaves out, and names, one it
            // cannot watch, as it skips one already watched; one asked for
            // by index fails the restore, named. Only what the wallet's
            // own material or name is refused for: anything else fails
            // the restore as it is.
            let asked_by_index = choices.indexes.is_some();
            let mut refused = Vec::new();
            // The wallets whose building failed: a later copy of one, which
            // the plan counted as restored with it, is built in turn, and
            // refused the same, never counted as watched.
            let mut unbuilt: Vec<(Network, &WalletKind)> = Vec::new();
            for (index, fate) in plan.wallets {
                let wallet = &payload.wallets[index];
                let name = wallet.name.trim();
                let copy_of_unbuilt = unbuilt
                    .iter()
                    .any(|(network, kind)| *network == wallet.network && **kind == wallet.kind);
                let built = match fate {
                    Fate::Watched if !copy_of_unbuilt => {
                        skipped += 1;
                        continue;
                    }
                    Fate::Refused(error) => Err(error),
                    // The plan checked the material the way the engine
                    // reads it; building it can still fail on what only
                    // a derivation meets, and is then refused all the
                    // same, never half-restored.
                    Fate::Watched | Fate::Restored => {
                        let mut meta = fresh_meta(
                            name,
                            wallet.network,
                            wallet.kind.clone(),
                            recognized_kind(&wallet.kind),
                            gap_limit,
                        );
                        meta.labels = wallet.labels.clone();
                        meta.live_pinned = wallet.live_pinned;
                        let built = build_record(meta);
                        if built.is_err() {
                            unbuilt.push((wallet.network, &wallet.kind));
                        }
                        built
                    }
                };
                match built {
                    Ok(record) => pending.push(record),
                    Err(error) if !asked_by_index && is_refusal(&error) => {
                        refused.push(RefusedWallet {
                            index: index as u32,
                            name: wallet_called(index, name),
                            reason: error.to_string(),
                        })
                    }
                    Err(error) => return Err(refused_wallet(index, name, error)),
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
                    settings.backends.extend(plan.backends);
                    // The plan pins no host the vault pins already.
                    settings.electrum_certs.extend(plan.certs);
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

/// What a restore of `payload` does to the vault `vault`, decided in one
/// place: [`WalletManager::preview_backup`] shows it and
/// [`WalletManager::import_backup`] carries it out, so the preview never
/// promises what the restore would not do. The settings are those a
/// restore puts in place when they are applied.
struct RestorePlan {
    /// What becomes of each wallet considered, by its index in the
    /// backup, in the order of the backup.
    wallets: Vec<(usize, Fate)>,
    /// The backends the settings put in place, by network, in the form
    /// the settings screen stores them; those of the other networks stay
    /// as they are.
    backends: BTreeMap<Network, BackendConfig>,
    /// The certificates the settings pin, by host; never one the vault
    /// pins already. See [`restorable_certs`].
    certs: BTreeMap<String, String>,
}

/// What a restore does with one wallet of the backup.
enum Fate {
    /// The vault watches the same material on the same network already,
    /// or a wallet of the backup before it is restored with it: skipped.
    Watched,
    /// Its name or its material is refused, for this reason.
    Refused(CoreError),
    /// Restored as a new wallet.
    Restored,
}

/// The plan of a restore of the wallets `chosen`, by index into the
/// backup, read without building any engine: each wallet is checked the
/// way an import checks one ([`check_restorable`]) and against the
/// wallets restored before it, so two copies of a wallet in one backup
/// come back as one.
fn plan_restore(
    vault: &VaultPayload,
    payload: &BackupPayload,
    chosen: impl IntoIterator<Item = usize>,
) -> RestorePlan {
    let mut restored: Vec<&BackupWallet> = Vec::new();
    let wallets = chosen
        .into_iter()
        .map(|index| {
            let wallet = &payload.wallets[index];
            let watched = find_watched(vault, wallet.network, &wallet.kind).is_some()
                || restored.iter().any(|earlier| {
                    earlier.network == wallet.network && earlier.kind == wallet.kind
                });
            let fate = if watched {
                Fate::Watched
            } else {
                match check_restorable(wallet) {
                    Ok(()) => {
                        restored.push(wallet);
                        Fate::Restored
                    }
                    Err(error) => Fate::Refused(error),
                }
            };
            (index, fate)
        })
        .collect();
    // Stored the way the settings screen stores them: a backup from a
    // vault older than that form, or one written by hand, must not put in
    // place an address the screen would have refused. One that cannot be
    // read is left out, and the backend of that network stays as it was.
    let backends: BTreeMap<Network, BackendConfig> = payload
        .backends
        .iter()
        .flatten()
        .filter_map(|(network, config)| Some((*network, config.clone().canonical().ok()?)))
        .collect();
    let certs = restorable_certs(&vault.settings, &backends, payload);
    RestorePlan {
        wallets,
        backends,
        certs,
    }
}

/// The certificates a restore pins, by host, as an acceptance made by
/// hand stores them. Only those of an Electrum server the settings reach
/// without anyone typing it: one a backend in service after the restore
/// names, the backup's (`backends`) for the networks it replaces and the
/// vault's for the others, or one of the public servers of the catalogue
/// that sign their own certificate, which a person picks from a list. A
/// pin is a decision about such a server; one for a host nothing names
/// would wait in the vault, unseen, for the day that host is typed in,
/// and take its certificate as accepted. Each one also passes the check
/// of the acceptance dialog: a backup must not pin what the dialog would
/// have refused, nor a fingerprint shaped so that no real certificate
/// can ever match it and the host becomes permanently unreachable.
///
/// Two entries of the backup that name the same host under two
/// spellings pin it once when they agree, and not at all when they do
/// not: the restore has no way to tell which one the person accepted,
/// and the acceptance dialog asks again at the first connection. A host
/// the vault pins already keeps its own pin and is left out, never
/// replaced in silence.
///
/// A pin stands in for the check by an authority: one restored for the
/// vault's own server, whose certificate an authority signs, makes that
/// server answer to the backup's fingerprint instead. It is named in the
/// preview and taken only with the settings, which may as well replace
/// that server outright; checking the authority first would take a
/// connection the preview does not make.
fn restorable_certs(
    vault: &Settings,
    backends: &BTreeMap<Network, BackendConfig>,
    payload: &BackupPayload,
) -> BTreeMap<String, String> {
    let mut in_service = vault.backends.clone();
    in_service.extend(backends.clone());
    let served = in_service
        .iter()
        .filter_map(|(network, config)| {
            chain::endpoints(config, *network, &chain::TrustedCerts::new()).ok()
        })
        .flatten()
        .filter_map(|endpoint| match endpoint {
            chain::Endpoint::Electrum(target) => Some(target.url.to_string()),
            chain::Endpoint::Esplora(_) => None,
        });
    let catalogue = Network::ALL
        .into_iter()
        .flat_map(chain::public::public_servers)
        .filter(|server| {
            server.self_signed && server.protocol == chain::public::ServerProtocol::Electrum
        })
        .map(|server| server.url);
    let named: HashSet<String> = served
        .chain(catalogue)
        .map(|url| chain::electrum::certificate_key(&url))
        .collect();
    // Each host with the one fingerprint its entries agree on, or none.
    let mut agreed: BTreeMap<String, Option<String>> = BTreeMap::new();
    for (host, fingerprint) in payload.electrum_certs.iter().flatten() {
        if !chain::tls::is_fingerprint(fingerprint) {
            continue;
        }
        let fingerprint = fingerprint.to_ascii_uppercase();
        agreed
            .entry(chain::electrum::certificate_key(host))
            .and_modify(|seen| {
                if seen.as_deref() != Some(fingerprint.as_str()) {
                    *seen = None;
                }
            })
            .or_insert(Some(fingerprint));
    }
    agreed
        .into_iter()
        .filter_map(|(host, fingerprint)| Some((host, fingerprint?)))
        .filter(|(host, _)| named.contains(host) && !vault.electrum_certs.contains_key(host))
        .collect()
}

/// A wallet of the backup a restore refused, named where the error has
/// words of its own, by its position when it has no name: a backup may
/// hold many, and the error is all a person who asked for it anyway
/// sees.
/// A refusal whose error has no words to add the name to, a network
/// that does not match or private key material, is said as an input of
/// the backup refused, in the words of the error.
fn refused_wallet(index: usize, name: &str, error: CoreError) -> CoreError {
    let named = match wallet_called(index, name) {
        called if name.trim().is_empty() => called,
        called => format!("\"{called}\""),
    };
    match error {
        CoreError::Descriptor(detail) => {
            CoreError::Descriptor(format!("{named} cannot be restored: {detail}"))
        }
        CoreError::InvalidInput { kind, detail } => CoreError::InvalidInput {
            kind,
            detail: format!("{named} cannot be restored: {detail}"),
        },
        error @ (CoreError::NetworkMismatch { .. } | CoreError::PrivateMaterialRejected) => {
            CoreError::InvalidInput {
                kind: "backup",
                detail: format!("{named} cannot be restored: {error}"),
            }
        }
        other => other,
    }
}

/// What a wallet of the backup is called in a refusal: its name, or
/// its place in the backup when it has none.
fn wallet_called(index: usize, name: &str) -> String {
    match name.trim() {
        "" => format!("Wallet {} of the backup", index + 1),
        name => name.to_owned(),
    }
}

/// Refuses a wallet without a name, as adding one does.
fn check_name(name: &str) -> CoreResult<()> {
    if name.trim().is_empty() {
        return Err(CoreError::InvalidInput {
            kind: "wallet name",
            detail: "a wallet needs a name".to_owned(),
        });
    }
    Ok(())
}

/// What a restore refuses a wallet of the backup for, read without
/// building its engine: its name, then its material, as
/// [`check_material`] reads it the way the engine would.
fn check_restorable(wallet: &BackupWallet) -> CoreResult<()> {
    check_name(&wallet.name)?;
    check_material(&wallet.kind, wallet.network)
}

/// Whether a restore that failed on one wallet failed on that wallet's
/// name or material, which a restore of every wallet leaves out and
/// names, rather than on anything else, which fails it as it is.
fn is_refusal(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::Descriptor(_)
            | CoreError::InvalidInput { .. }
            | CoreError::PrivateMaterialRejected
            | CoreError::NetworkMismatch { .. }
    )
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
