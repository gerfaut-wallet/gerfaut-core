//! Core library of Gerfaut, a Bitcoin watch-only wallet.
//!
//! This crate is the single wallet implementation shared by the mobile app,
//! the desktop app, and the server. It handles output descriptors, address
//! derivation, chain data sources, and encrypted persistence.
//!
//! It is watch-only by design: there is no code to generate keys, handle
//! seeds, or sign transactions, and there never will be. Inputs containing
//! private key material are rejected at the parsing boundary.

pub mod backup;
pub mod broadcast;
pub mod chain;
pub mod error;
pub mod export;
pub mod fees;
pub mod format;
pub mod input;
pub mod lock;
pub mod manager;
pub mod network;
pub mod price;
pub mod store;
pub mod updates;
pub mod wallet;

pub use error::{CoreError, CoreResult};
pub use manager::WalletManager;
pub use network::Network;
