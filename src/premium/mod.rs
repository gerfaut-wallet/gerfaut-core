//! Gerfaut Premium: the account key, the devices it connects, the
//! licence it earns, and the server that watches wallets on the
//! account's behalf.
//!
//! Premium is bought without an e-mail: a key of sixteen symbols, shown
//! once, is the whole account, and the server keeps a hash of it and
//! nothing else. The key connects a device, and the device then speaks
//! with a token of its own, so a key seen by someone else opens nothing
//! without the account's devices hearing of it. What the apps hold
//! beside the key and the token is a certificate, a signed statement of
//! how long the key is paid for, verified here with the public key this
//! crate embeds. A phone in a tunnel still knows it is premium, and the
//! server never learns when the app was opened.
//!
//! Both apps go through this one implementation: a body the server
//! sends is decoded once, an error is named once, and a signature is
//! checked the same way everywhere. What the server watches is the
//! descriptor the app already imported, and nothing here handles a key
//! that could spend.

pub mod client;
pub mod device;
pub mod licence;
pub mod state;

pub use client::{
    Account, Channel, ChannelKind, Event, EventKind, Health, HeartbeatReport, Licence,
    PremiumClient, WalletWatch, endpoint,
};
pub use device::{
    ConnectedDevice, Device, DeviceAccess, DeviceCredential, DevicePlatform, PendingConnect, Secret,
};
pub use licence::{Claims, Heartbeat, LicenceState};
pub use state::{PremiumState, WatchedWallet};
