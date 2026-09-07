//! Admin forwarding to a `unidpp-registry` instance (the 19135 item
//! service, TODO.impl item 12). The issuer registers profiles and
//! applicability bindings with the registry over HTTP **when one is
//! configured and reachable**; otherwise it records local fixtures so
//! the lifecycle keeps working in development and offline demos.
//!
//! Division of labour (MECE): the registry owns item lifecycle
//! (versioned supersession, point-in-time resolution); the issuer owns
//! passport lifecycle. The issuer's local records are the fallback
//! view, always journaled, and always reported as such — a response
//! never claims registry authority it does not have.

use std::time::Duration;

use serde_json::Value;

use crate::http::{self, Url};

/// Where a registration landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryMode {
    /// The registry accepted the registration (2xx).
    Registry,
    /// No registry URL is configured; the local fixture was recorded.
    Fixtures,
    /// A registry URL is configured but unreachable; the local fixture
    /// was recorded and the response says so.
    Unreachable,
}

impl RegistryMode {
    /// Canonical wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            RegistryMode::Registry => "registry",
            RegistryMode::Fixtures => "fixtures",
            RegistryMode::Unreachable => "unreachable",
        }
    }
}

impl std::fmt::Display for RegistryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of one admin registration attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryOutcome {
    /// Where the registration landed.
    pub mode: RegistryMode,
    /// Human-facing detail (registry response summary, or why the
    /// registry was not used).
    pub detail: Option<String>,
}

impl RegistryOutcome {
    /// The `via` token journaled with the mutation.
    pub fn via(&self) -> String {
        match (&self.mode, &self.detail) {
            (RegistryMode::Registry, _) => "registry".to_string(),
            (mode, Some(d)) => format!("{mode}: {d}"),
            (mode, None) => mode.as_str().to_string(),
        }
    }
}

/// Default forwarding timeout (loopback sibling service; a slow
/// registry degrades to fixtures rather than hanging the request).
pub const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

/// The registry forwarder.
#[derive(Debug, Clone)]
pub struct RegistryClient {
    base: Option<String>,
    bearer: Option<String>,
}

impl RegistryClient {
    /// `base` is the registry root (e.g. `http://127.0.0.1:8090`);
    /// `None` disables forwarding (fixtures mode).
    pub fn new(base: Option<String>, bearer: Option<String>) -> RegistryClient {
        RegistryClient { base, bearer }
    }

    /// Forward a profile registration (`POST /profiles` on the
    /// registry — its profile subregister). On success the registry is
    /// authoritative; the caller still journals its local record.
    pub async fn register_profile(&self, body: &Value) -> Result<RegistryOutcome, String> {
        self.forward("/profiles", body).await
    }

    /// Forward an applicability binding (`POST /applicability`).
    pub async fn bind_applicability(&self, body: &Value) -> Result<RegistryOutcome, String> {
        self.forward("/applicability", body).await
    }

    async fn forward(&self, path: &str, body: &Value) -> Result<RegistryOutcome, String> {
        let Some(base) = &self.base else {
            return Ok(RegistryOutcome {
                mode: RegistryMode::Fixtures,
                detail: Some("no registry URL configured".to_string()),
            });
        };
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        Url::parse(&url).map_err(|e| format!("bad registry URL `{url}`: {e}"))?;
        let payload =
            serde_json::to_string(body).map_err(|e| format!("registry body serialization: {e}"))?;
        let resp = match http::json_request(
            "POST",
            &url,
            Some(&payload),
            self.bearer.as_deref(),
            FORWARD_TIMEOUT,
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Ok(RegistryOutcome {
                    mode: RegistryMode::Unreachable,
                    detail: Some(format!("registry not reachable: {e}")),
                })
            }
        };
        if (200..300).contains(&resp.status) {
            Ok(RegistryOutcome {
                mode: RegistryMode::Registry,
                detail: Some(resp.body_string()),
            })
        } else {
            // A live registry rejected the registration: surface the
            // rejection verbatim (the operator must fix the input, not
            // retry blindly into fixtures).
            Err(format!(
                "registry rejected the registration ({}): {}",
                resp.status,
                resp.body_string()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn via_tokens() {
        let fixtures = RegistryOutcome {
            mode: RegistryMode::Fixtures,
            detail: Some("no registry URL configured".into()),
        };
        assert_eq!(fixtures.via(), "fixtures: no registry URL configured");
        let registry = RegistryOutcome {
            mode: RegistryMode::Registry,
            detail: Some("{\"identifier\":\"p\"}".into()),
        };
        assert_eq!(registry.via(), "registry");
        let down = RegistryOutcome {
            mode: RegistryMode::Unreachable,
            detail: None,
        };
        assert_eq!(down.via(), "unreachable");
    }

    #[tokio::test]
    async fn no_base_means_fixtures() {
        let client = RegistryClient::new(None, None);
        let out = client
            .register_profile(&json!({"register_id": "r", "item_id": "p"}))
            .await
            .unwrap();
        assert_eq!(out.mode, RegistryMode::Fixtures);
    }

    #[tokio::test]
    async fn unreachable_registry_degrades_to_fixtures() {
        // Port 1 on loopback: reserved, nothing listens there.
        let client = RegistryClient::new(Some("http://127.0.0.1:1".into()), None);
        let out = client
            .bind_applicability(&json!({"profile_id": "p", "product_type": "t"}))
            .await
            .unwrap();
        assert_eq!(out.mode, RegistryMode::Unreachable);
        assert!(out.detail.as_deref().unwrap().contains("not reachable"));
    }
}
