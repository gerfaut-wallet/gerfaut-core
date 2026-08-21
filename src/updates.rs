//! Release update check against GitHub.
//!
//! Read-only, on demand, never automatic: the apps expose a button and
//! display the outcome. Failures (offline, private repository, rate
//! limit) degrade to "could not check", never to an error state.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};

/// Outcome of a release check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateCheck {
    /// Latest published tag, for example `v0.2.0`.
    pub latest: String,
    /// Web page of the latest release.
    pub url: String,
    /// True when the latest tag is newer than the running version.
    pub update_available: bool,
}

/// Compares two `x.y.z` versions, ignoring a leading `v`.
///
/// Unparseable versions compare as not newer: a malformed tag must not
/// nag users with a phantom update.
fn is_newer(latest: &str, current: &str) -> bool {
    fn parts(version: &str) -> Option<[u64; 3]> {
        let trimmed = version.trim().trim_start_matches('v');
        let mut out = [0u64; 3];
        let mut count = 0;
        for (i, part) in trimmed.split('.').enumerate() {
            if i >= 3 {
                return None;
            }
            out[i] = part.parse().ok()?;
            count = i + 1;
        }
        (count >= 2).then_some(out)
    }
    match (parts(latest), parts(current)) {
        (Some(latest), Some(current)) => latest > current,
        _ => false,
    }
}

/// Queries the latest release of `owner/repo` and compares it with the
/// running version.
pub async fn check_update(repo: &str, current_version: &str) -> CoreResult<UpdateCheck> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("gerfaut")
        .build()
        .map_err(|e| CoreError::Internal(format!("http client: {e}")))?;
    let response = client
        .get(format!(
            "https://api.github.com/repos/{repo}/releases/latest"
        ))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| check_error(e.to_string()))?;
    if !response.status().is_success() {
        return Err(check_error(format!("http {}", response.status())));
    }
    let value: serde_json::Value = response
        .json()
        .await
        .map_err(|e| check_error(e.to_string()))?;
    let latest = value["tag_name"]
        .as_str()
        .ok_or_else(|| check_error("no tag in response".to_owned()))?
        .to_owned();
    let url = value["html_url"]
        .as_str()
        .unwrap_or(&format!("https://github.com/{repo}/releases/latest"))
        .to_owned();
    Ok(UpdateCheck {
        update_available: is_newer(&latest, current_version),
        latest,
        url,
    })
}

fn check_error(detail: String) -> CoreError {
    CoreError::Sync {
        backend: "github".to_owned(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.1.10", "0.1.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.2.0"));
        assert!(!is_newer("nightly", "0.1.0"), "malformed tags never nag");
        assert!(!is_newer("0.2.0", "garbage"));
    }
}
