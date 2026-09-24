//! The devices of a premium account.
//!
//! The key does not open the account by itself: it connects a device,
//! and the server hands that device a token of its own, a random bearer
//! string shown to it once. Every later request carries the token, never
//! the key. Whoever reads the key over someone's shoulder can only
//! connect one more device, which every other device hears about, and
//! which sees nothing and changes nothing for ten days unless one of them
//! approves it. The first device an account ever has is trusted at once.
//!
//! The token never leaves the core. The vault keeps it, the client sends
//! it, and whatever prints, logs or hands the state to an app has it
//! masked or blanked: it is worth more than the key, since a device with
//! full access needs no approval.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What a device runs on, the way the server names it. The server takes
/// these five and no free text: what an alert about a new device says
/// is a label this side chose, never words the connecting party wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DevicePlatform {
    Android,
    Ios,
    Windows,
    Macos,
    Linux,
    /// A platform this build does not know, listed by a newer server.
    /// Read so that a list holding one still shows every device, the
    /// one to refuse among them; never sent.
    #[serde(other)]
    Other,
}

impl DevicePlatform {
    /// How a device is named on the screens and in the alerts.
    pub fn label(self) -> &'static str {
        match self {
            DevicePlatform::Android => "Android phone",
            DevicePlatform::Ios => "iPhone",
            DevicePlatform::Windows => "Windows computer",
            DevicePlatform::Macos => "Mac",
            DevicePlatform::Linux => "Linux computer",
            DevicePlatform::Other => "Device",
        }
    }

    /// The platform this build runs on; `None` on one the server does
    /// not take.
    pub fn current() -> Option<Self> {
        if cfg!(target_os = "android") {
            Some(DevicePlatform::Android)
        } else if cfg!(target_os = "ios") {
            Some(DevicePlatform::Ios)
        } else if cfg!(target_os = "windows") {
            Some(DevicePlatform::Windows)
        } else if cfg!(target_os = "macos") {
            Some(DevicePlatform::Macos)
        } else if cfg!(target_os = "linux") {
            Some(DevicePlatform::Linux)
        } else {
            None
        }
    }
}

/// What a device may do on the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceAccess {
    /// Sees and changes everything the account holds.
    Full,
    /// Waits for another device to approve it, or for
    /// [`Device::pending_until`], and sees nothing meanwhile. An access
    /// this build does not know reads as this one: never more than the
    /// server may have meant.
    #[serde(other)]
    Pending,
}

/// One device of the account, as the server describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub platform: DevicePlatform,
    /// Unix seconds.
    pub connected_at: i64,
    pub access: DeviceAccess,
    /// Unix seconds: when a waiting device gets full access without an
    /// approval. `None` once it has full access.
    #[serde(default)]
    pub pending_until: Option<i64>,
    /// Unix seconds: when another device approved it, or when it
    /// connected as the account's first. `None` for a device still
    /// waiting, and for one that waited its time out.
    #[serde(default)]
    pub approved_at: Option<i64>,
    /// True for the device that asked.
    #[serde(default)]
    pub this_device: bool,
}

impl Device {
    /// Whether the device still waits for its access.
    pub fn is_pending(&self) -> bool {
        self.access == DeviceAccess::Pending
    }
}

/// This device's own connection to the account, as the vault keeps it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCredential {
    /// The id the server gave this device.
    pub id: String,
    /// The bearer token. Only the core reads it: the state the apps are
    /// handed has it blanked, and [`fmt::Debug`] masks it.
    token: String,
    /// Unix seconds: when this device connected.
    pub connected_at: i64,
}

impl DeviceCredential {
    pub(crate) fn new(id: String, token: String, connected_at: i64) -> Self {
        DeviceCredential {
            id,
            token,
            connected_at,
        }
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// The same credential without its token: what an app may hold.
    pub(crate) fn redacted(&self) -> Self {
        DeviceCredential {
            token: String::new(),
            ..self.clone()
        }
    }
}

impl fmt::Debug for DeviceCredential {
    /// The token stays out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceCredential")
            .field("id", &self.id)
            .field("token", &"hidden")
            .field("connected_at", &self.connected_at)
            .finish()
    }
}

/// `POST /v1/devices`: the device just connected, and its token.
#[derive(Clone, Deserialize)]
pub struct ConnectedDevice {
    pub device: Device,
    token: String,
}

impl ConnectedDevice {
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// What the vault keeps of it.
    pub(crate) fn credential(&self) -> DeviceCredential {
        DeviceCredential::new(
            self.device.id.clone(),
            self.token.clone(),
            self.device.connected_at,
        )
    }
}

impl fmt::Debug for ConnectedDevice {
    /// The token stays out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectedDevice")
            .field("device", &self.device)
            .field("token", &"hidden")
            .finish()
    }
}

/// A string the core keeps and never shows: a device token, or a key
/// not yet the account's. [`fmt::Debug`] masks it, and the copy of the
/// state the apps are handed has it blanked; they can tell it is there,
/// never what it is.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub(crate) fn new(value: String) -> Self {
        Secret(value)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    /// The same, blanked: what an app may hold.
    pub(crate) fn redacted(&self) -> Self {
        Secret(String::new())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("hidden")
    }
}

/// A connection sent to the server and not answered yet: the key it
/// went with, the token this device drew for itself, and the platform
/// it named. Written to the vault before the request leaves, so a lost
/// answer is settled by sending the very same request again, which the
/// server takes as the connection it already made rather than a second
/// device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingConnect {
    key: Secret,
    token: Secret,
    pub platform: DevicePlatform,
}

impl PendingConnect {
    pub(crate) fn new(key: String, token: String, platform: DevicePlatform) -> Self {
        PendingConnect {
            key: Secret::new(key),
            token: Secret::new(token),
            platform,
        }
    }

    pub(crate) fn key(&self) -> &str {
        self.key.expose()
    }

    pub(crate) fn token(&self) -> &str {
        self.token.expose()
    }

    pub(crate) fn redacted(&self) -> Self {
        PendingConnect {
            key: self.key.redacted(),
            token: self.token.redacted(),
            platform: self.platform,
        }
    }
}

/// A fresh device token, drawn from the operating system's generator in
/// the shape the server hands out: `gdt1_` and 32 random bytes in
/// base64url. A random bearer string, and nothing a signature could be
/// made with.
pub(crate) fn draw_device_token() -> crate::CoreResult<String> {
    use rand::TryRngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| crate::CoreError::Internal(format!("no randomness to draw a token: {e}")))?;
    Ok(format!(
        "gdt1_{}",
        data_encoding::BASE64URL_NOPAD.encode(&bytes)
    ))
}

/// Whether a token has the shape the server hands out: `gdt1_` and at
/// least 128 bits in base64url. Anything else, a header breaker among
/// them, is not stored.
pub(crate) fn is_device_token(token: &str) -> bool {
    token.strip_prefix("gdt1_").is_some_and(|rest| {
        (22..=256).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "gdt1_q83vEjRWeJC6ze8SNFZ4kLrN7xI0VniQus3vEjRWeJA";

    #[test]
    fn a_device_decodes_as_the_server_writes_it() {
        let full: Device = serde_json::from_str(
            r#"{"id":"0b4b1e1c-7d1e-4b6a-9d0e-1a2b3c4d5e6f","platform":"android","connected_at":1790000000,"access":"full","pending_until":null,"approved_at":1790000000,"this_device":true}"#,
        )
        .unwrap();
        assert_eq!(
            full,
            Device {
                id: "0b4b1e1c-7d1e-4b6a-9d0e-1a2b3c4d5e6f".to_owned(),
                platform: DevicePlatform::Android,
                connected_at: 1_790_000_000,
                access: DeviceAccess::Full,
                pending_until: None,
                approved_at: Some(1_790_000_000),
                this_device: true,
            }
        );
        assert!(!full.is_pending());

        let pending: Device = serde_json::from_str(
            r#"{"id":"1c5c2f2d-8e2f-4c7b-8e1f-2b3c4d5e6f70","platform":"macos","connected_at":1790000100,"access":"pending","pending_until":1790864100,"approved_at":null,"this_device":false}"#,
        )
        .unwrap();
        assert_eq!(pending.platform, DevicePlatform::Macos);
        assert!(pending.is_pending());
        assert_eq!(pending.pending_until, Some(1_790_864_100));
        assert_eq!(pending.approved_at, None);
        assert!(!pending.this_device);
    }

    /// A newer server may list a platform or an access this build does
    /// not know. The list must still read, every device in it: the one
    /// nobody recognizes is the one to refuse.
    #[test]
    fn what_a_newer_server_adds_still_reads() {
        let device: Device = serde_json::from_str(
            r#"{"id":"d","platform":"visionos","connected_at":1,"access":"probation"}"#,
        )
        .unwrap();
        assert_eq!(device.platform, DevicePlatform::Other);
        assert_eq!(device.platform.label(), "Device");
        assert_eq!(
            device.access,
            DeviceAccess::Pending,
            "an access this build does not know is not full access"
        );
        assert_eq!(device.pending_until, None);
        assert!(!device.this_device);
    }

    #[test]
    fn platforms_use_the_api_spelling_and_the_labels_of_the_screens() {
        for (platform, spelled, label) in [
            (DevicePlatform::Android, "android", "Android phone"),
            (DevicePlatform::Ios, "ios", "iPhone"),
            (DevicePlatform::Windows, "windows", "Windows computer"),
            (DevicePlatform::Macos, "macos", "Mac"),
            (DevicePlatform::Linux, "linux", "Linux computer"),
        ] {
            assert_eq!(
                serde_json::to_string(&platform).unwrap(),
                format!("\"{spelled}\"")
            );
            assert_eq!(
                serde_json::from_str::<DevicePlatform>(&format!("\"{spelled}\"")).unwrap(),
                platform
            );
            assert_eq!(platform.label(), label);
        }
        assert_eq!(
            serde_json::to_string(&DeviceAccess::Pending).unwrap(),
            r#""pending""#
        );
    }

    #[test]
    fn the_platform_of_this_build_is_one_the_server_takes() {
        let current = DevicePlatform::current();
        if cfg!(any(
            target_os = "android",
            target_os = "ios",
            target_os = "windows",
            target_os = "macos",
            target_os = "linux"
        )) {
            assert!(current.is_some_and(|p| p != DevicePlatform::Other));
        } else {
            assert_eq!(current, None);
        }
    }

    #[test]
    fn the_token_stays_out_of_debug_output() {
        let credential = DeviceCredential::new("d1".to_owned(), TOKEN.to_owned(), 5);
        let shown = format!("{credential:?} {credential:#?}");
        assert!(!shown.contains(TOKEN), "{shown}");
        assert!(!shown.contains("q83v"), "{shown}");
        assert!(shown.contains("d1"), "{shown}");
        assert_eq!(credential.token(), TOKEN);
        assert_eq!(credential.redacted().token(), "");
        assert_eq!(credential.redacted().id, "d1");

        let connected: ConnectedDevice = serde_json::from_str(&format!(
            r#"{{"device":{{"id":"d1","platform":"linux","connected_at":5,"access":"full","approved_at":5,"this_device":true}},"token":"{TOKEN}"}}"#
        ))
        .unwrap();
        let shown = format!("{connected:?}");
        assert!(!shown.contains(TOKEN), "{shown}");
        assert_eq!(connected.credential(), credential);
    }

    #[test]
    fn a_drawn_token_has_the_server_shape_and_is_new_each_time() {
        let token = draw_device_token().unwrap();
        assert!(is_device_token(&token), "{token}");
        assert_eq!(token.len(), "gdt1_".len() + 43);
        assert_ne!(token, draw_device_token().unwrap());
    }

    #[test]
    fn a_secret_stays_out_of_debug_output() {
        let pending = PendingConnect::new(
            "abcdefghijkmnpqr".to_owned(),
            TOKEN.to_owned(),
            DevicePlatform::Linux,
        );
        let shown = format!("{pending:?} {pending:#?}");
        assert!(!shown.contains(TOKEN), "{shown}");
        assert!(!shown.contains("abcdefghijkmnpqr"), "{shown}");
        assert_eq!(pending.token(), TOKEN);
        assert_eq!(pending.key(), "abcdefghijkmnpqr");
        let blank = pending.redacted();
        assert_eq!((blank.key(), blank.token()), ("", ""));
        assert_eq!(blank.platform, DevicePlatform::Linux);
        // In the vault, the values themselves.
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(
            json,
            format!(r#"{{"key":"abcdefghijkmnpqr","token":"{TOKEN}","platform":"linux"}}"#)
        );
        assert_eq!(
            serde_json::from_str::<PendingConnect>(&json).unwrap(),
            pending
        );
    }

    #[test]
    fn only_a_token_of_the_server_shape_is_kept() {
        assert!(is_device_token(TOKEN));
        assert!(is_device_token(&format!("gdt1_{}", "A".repeat(22))));
        assert!(is_device_token(&format!("gdt1_{}", "A".repeat(256))));
        // Too short to be random enough, another prefix, a key, and what
        // would break the header it goes into.
        assert!(!is_device_token(&format!("gdt1_{}", "A".repeat(21))));
        assert!(!is_device_token(
            "gdt2_q83vEjRWeJC6ze8SNFZ4kLrN7xI0VniQus3vEjRWeJA"
        ));
        assert!(!is_device_token("abcdefghijkmnpqr"));
        assert!(!is_device_token(
            "gdt1_q83vEjRWeJC6ze8SNFZ4kLrN7xI0Vn\r\nX-Evil: 1"
        ));
        assert!(!is_device_token("gdt1_q83vEjRWeJC6ze8SNFZ4kLrN7xI0Vn+/="));
        assert!(!is_device_token(&format!("gdt1_{}", "A".repeat(257))));
        assert!(!is_device_token("gdt1_"));
        assert!(!is_device_token(""));
    }
}
