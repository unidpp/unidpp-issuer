//! Server key material: deterministic seeded dev mode and env-key prod
//! mode. All real cryptography flows through [`unidpp_signatif`]; this
//! module owns the seed bytes, the derived [`unidpp_signatif::keyring::KeyPair`]
//! handles, and the public view a verifier pins.
//!
//! Two roles:
//!
//! - **event key** — Ed25519. The signature covers a sealed event's
//!   canonical body, in `SigningDomain::ArtifactEvent`. The signature
//!   travels as the document's `EventSignature` record; a verifier
//!   rebuilds it from the public key it pinned for the issuer and
//!   checks it with `unidpp_signatif::SignatureSlot::verify`.
//! - **pack key** — ECDSA-P256 (deterministic RFC 6979). This is the
//!   computed suite that rides the core's Tier-A carrier frame
//!   (`ecdsa-p256 | sm2 | ml-dsa-*` — the documented deviation from the
//!   core's table lives in `unidpp_signatif::sign`). Packs minted with
//!   `unidpp_cli::packfile::sign_pack` use this seed verbatim, so the
//!   same key signs the pack bytes and the issuer's public anchor
//!   verifies them.
//!
//! Mode resolution:
//!
//! - **env-key mode**: both `UNIDPP_ISSUER_EVENT_SEED` and
//!   `UNIDPP_ISSUER_PACK_SEED` set to hex of sufficient length. The
//!   raw bytes are used as the signing seeds (production keeps the CSPRNG
//!   outside this crate; the issuer does not generate or import PGP
//!   keys itself).
//! - **seeded-dev mode**: at least one seed is missing. The service
//!   derives both keys deterministically from a single human-readable
//!   dev seed (`UNIDPP_ISSUER_SEED`, else a fixed default) — same seed
//!   always produces the same keyring, so tests and ceremonies stay
//!   reproducible. `Config::from_env` returns a warning string when the
//!   fallback fires so deployments do not silently run in dev mode.
//!
//! The keyring exposes its seed bytes for pack signing rather than the
//! raw `KeyPair` so the `unidpp_cli::packfile::sign_pack` entry point
//! can be reused (DRY; the CLI's pack signer is the one a verifier
//! already trusts to produce the bytes it parses).

use serde_json::{json, Value};
use unidpp_signatif::keyring::{KeyId, KeyPair, PublicKey};
use unidpp_signatif::sign::Suite;

/// The fallback dev seed when `UNIDPP_ISSUER_SEED` is unset. Never used
/// in production deployments (env-key mode overrides it).
pub const DEFAULT_DEV_SEED: &str = "unidpp-issuer/dev-1";

/// Minimum decoded seed length (hex-encoded minimum 16 bytes — short
/// material is rejected to avoid accidentally-weak dev seeds).
pub const MIN_SEED_BYTES: usize = 16;

/// The two signing roles the issuer recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Server key used to sign appended events (Ed25519).
    Event,
    /// Server key used to sign Tier-A packs (ECDSA-P256).
    Pack,
}

impl Role {
    /// Canonical wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Event => "event",
            Role::Pack => "pack",
        }
    }
}

/// How the keyring was assembled — exposed to operators via `/keyring`
/// and the discovery document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringMode {
    /// Deterministic keys derived from a fixed seed (dev mode only;
    /// never use in production).
    SeededDev,
    /// Keys loaded from environment-supplied hex seeds.
    EnvKey,
}

impl KeyringMode {
    /// Canonical wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyringMode::SeededDev => "seeded-dev",
            KeyringMode::EnvKey => "env-key",
        }
    }
}

/// The configured pack-signing suites: the deployment's sovereign
/// co-signature policy (e.g. `ecdsa-p256` alone, `sm2` for a CN
/// deployment, or `ecdsa-p256,sm2` to fill both carrier slots on one
/// pack body). Order is significant — the first entry is the default
/// anchor surfaced by the back-compat response fields.
///
/// Selection rules (refused loudly, never silently ignored): every
/// suite must have real computation in this build and a core carrier
/// slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSuites(Vec<Suite>);

impl PackSuites {
    /// The deployment default.
    pub const DEFAULT_TOKEN: &'static str = "ecdsa-p256";

    /// Parse a comma/space-separated suite list.
    pub fn parse(token: &str) -> Result<PackSuites, String> {
        let mut out: Vec<Suite> = Vec::new();
        for part in token.split([',', ' ']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let suite =
                Suite::parse_token(part).map_err(|e| format!("pack suite `{part}`: {e}"))?;
            if suite.to_core().is_none() {
                return Err(format!(
                    "pack suite `{part}` has no core carrier slot \
                     (packs ride ecdsa-p256/sm2/ml-dsa-*)"
                ));
            }
            if !suite.is_computed() {
                return Err(format!(
                    "pack suite `{part}` has no computation in this build: {}",
                    suite.deferral().unwrap_or("computation unavailable")
                ));
            }
            if !out.contains(&suite) {
                out.push(suite);
            }
        }
        if out.is_empty() {
            return Err("at least one pack suite is required".to_string());
        }
        Ok(PackSuites(out))
    }

    /// The suites, in configured order.
    pub fn as_slice(&self) -> &[Suite] {
        &self.0
    }

    /// Collect an iterator of suites into the selection type (used by
    /// the serving layer to re-state the keyring's policy).
    pub fn collect_suites(suites: impl Iterator<Item = Suite>) -> PackSuites {
        let mut out = Vec::new();
        for suite in suites {
            if !out.contains(&suite) {
                out.push(suite);
            }
        }
        PackSuites(out)
    }

    /// The default (first) suite.
    pub fn default_suite(&self) -> Suite {
        self.0[0]
    }

    /// Wire tokens, configured order.
    pub fn tokens(&self) -> Vec<&'static str> {
        self.0.iter().map(|s| s.as_str()).collect()
    }
}

impl Default for PackSuites {
    fn default() -> PackSuites {
        PackSuites(vec![Suite::EcdsaP256])
    }
}

/// The server keyring. Construct via [`Keyring::dev`] or
/// [`Keyring::from_env_seeds`].
#[derive(Debug)]
pub struct Keyring {
    mode: KeyringMode,
    event_key: KeyPair,
    /// One signing key per configured pack suite, all derived from
    /// `pack_seed` with suite-separated material (the first is the
    /// default suite; the collection is the co-signature set).
    pack_keys: Vec<KeyPair>,
    /// The raw seed bytes used for the pack signers. Identical to the
    /// bytes `unidpp_cli::packfile::sign_pack_suites` is invoked with
    /// so the derived public keys line up exactly.
    pack_seed: Vec<u8>,
    /// The human-readable seed that produced this keyring (only set in
    /// seeded-dev mode — env-key mode reports `None`).
    dev_seed: Option<String>,
}

/// Derive one signing key per configured suite from the base pack
/// seed, using the CLI's suite-separation convention (P-256 verbatim —
/// historical anchors keep verifying; every other suite
/// domain-hashed) so the issuer's anchors and `sign_pack_suites` mint
/// the same keys from the same seed. One convention, one place (DRY).
fn derive_pack_keys(pack_seed: &[u8], suites: &PackSuites) -> Result<Vec<KeyPair>, String> {
    suites
        .as_slice()
        .iter()
        .map(|&suite| {
            KeyPair::seeded(
                suite,
                &unidpp_cli::packfile::pack_suite_seed(pack_seed, suite),
            )
            .map_err(|e| format!("pack key derivation for {suite}: {e}"))
        })
        .collect()
}

impl Keyring {
    /// Deterministic dev-mode keyring derived from `seed`. When
    /// `seed.is_empty()`, falls back to [`DEFAULT_DEV_SEED`].
    pub fn dev(seed: Option<&str>) -> Result<Keyring, String> {
        Self::with_pack_suites(seed, &PackSuites::default())
    }

    /// Dev-mode keyring with an explicit pack-suite policy.
    pub fn with_pack_suites(
        seed: Option<&str>,
        pack_suites: &PackSuites,
    ) -> Result<Keyring, String> {
        let dev_seed = match seed {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => DEFAULT_DEV_SEED.to_string(),
        };
        let event_material = format!("unidpp-issuer/event|{dev_seed}");
        let pack_material = format!("unidpp-issuer/pack|{dev_seed}");
        let event_key = KeyPair::seeded(Suite::Ed25519, event_material.as_bytes())
            .map_err(|e| format!("event key derivation: {e}"))?;
        let pack_seed = pack_material.into_bytes();
        let pack_keys = derive_pack_keys(&pack_seed, pack_suites)?;
        Ok(Keyring {
            mode: KeyringMode::SeededDev,
            event_key,
            pack_keys,
            pack_seed,
            dev_seed: Some(dev_seed),
        })
    }

    /// Env-key mode: raw seeds supplied by the operator (typically
    /// generated by a separate CSPRNG-backed ceremony and pasted as
    /// hex). `event_hex` and `pack_hex` are both required and must each
    /// decode to at least [`MIN_SEED_BYTES`] bytes.
    pub fn from_env_seeds(event_hex: &str, pack_hex: &str) -> Result<Keyring, String> {
        Self::from_env_seeds_with(event_hex, pack_hex, &PackSuites::default())
    }

    /// Env-key mode with an explicit pack-suite policy.
    pub fn from_env_seeds_with(
        event_hex: &str,
        pack_hex: &str,
        pack_suites: &PackSuites,
    ) -> Result<Keyring, String> {
        let event_seed = unidpp_cli::encoding::hex_decode(event_hex.trim())
            .map_err(|e| format!("event seed: not hex: {e}"))?;
        let pack_seed = unidpp_cli::encoding::hex_decode(pack_hex.trim())
            .map_err(|e| format!("pack seed: not hex: {e}"))?;
        if event_seed.len() < MIN_SEED_BYTES {
            return Err(format!(
                "event seed too short: {} bytes (need at least {MIN_SEED_BYTES})",
                event_seed.len()
            ));
        }
        if pack_seed.len() < MIN_SEED_BYTES {
            return Err(format!(
                "pack seed too short: {} bytes (need at least {MIN_SEED_BYTES})",
                pack_seed.len()
            ));
        }
        let event_key = KeyPair::seeded(Suite::Ed25519, &event_seed)
            .map_err(|e| format!("event key derivation: {e}"))?;
        let pack_keys = derive_pack_keys(&pack_seed, pack_suites)?;
        Ok(Keyring {
            mode: KeyringMode::EnvKey,
            event_key,
            pack_keys,
            pack_seed,
            dev_seed: None,
        })
    }

    /// Resolved mode.
    pub fn mode(&self) -> KeyringMode {
        self.mode
    }

    /// The human-readable dev seed (only when in seeded-dev mode).
    pub fn dev_seed(&self) -> Option<&str> {
        self.dev_seed.as_deref()
    }

    /// The Ed25519 event-signing key.
    pub fn event_key(&self) -> &KeyPair {
        &self.event_key
    }

    /// The pack-signing keys, one per configured suite (the first is
    /// the default suite).
    pub fn pack_keys(&self) -> &[KeyPair] {
        &self.pack_keys
    }

    /// The default-suite pack-signing key.
    pub fn pack_key(&self) -> &KeyPair {
        &self.pack_keys[0]
    }

    /// The configured pack anchors as `(suite, public)` pairs — what a
    /// co-signature verifier pins (one per suite).
    pub fn pack_anchors(&self) -> Vec<(Suite, unidpp_signatif::keyring::PublicKey)> {
        self.pack_keys
            .iter()
            .map(|k| (k.suite(), *k.public()))
            .collect()
    }

    /// The raw pack sign seed (bytes fed to
    /// `unidpp_cli::packfile::sign_pack`).
    pub fn pack_seed(&self) -> &[u8] {
        &self.pack_seed
    }

    /// The public anchor view for the `Role`.
    pub fn public(&self, role: Role) -> &PublicKey {
        match role {
            Role::Event => self.event_key.public(),
            Role::Pack => self.pack_keys[0].public(),
        }
    }

    /// The content-derived key id for the `Role`.
    pub fn key_id(&self, role: Role) -> &KeyId {
        match role {
            Role::Event => self.event_key.key_id(),
            Role::Pack => self.pack_keys[0].key_id(),
        }
    }

    /// Hex-encoded public key bytes for `role` (verifier-pinnable).
    pub fn public_hex(&self, role: Role) -> String {
        unidpp_cli::encoding::hex_encode(self.public(role).as_bytes())
    }

    /// Public view for `/keyring`: mode, roles, suites, key ids, and
    /// hex-encoded public anchors a verifier pins.
    pub fn to_json(&self) -> Value {
        let mut roles = serde_json::Map::new();
        roles.insert(
            Role::Event.as_str().to_string(),
            json!({
                "suite": self.event_key.public().suite().to_string(),
                "key_id": self.event_key.key_id().to_string(),
                "public": unidpp_cli::encoding::hex_encode(self.event_key.public().as_bytes()),
                "public_serialized": self.event_key.public().to_serialized(),
            }),
        );
        // The pack role is a co-signature set: top-level fields keep
        // the default suite (back-compat), `suites` carries one entry
        // per configured suite — the anchors a sovereign verifier pins.
        let default_key = &self.pack_keys[0];
        let mut suites = serde_json::Map::new();
        for key in &self.pack_keys {
            let public = key.public();
            suites.insert(
                public.suite().to_string(),
                json!({
                    "key_id": key.key_id().to_string(),
                    "public": unidpp_cli::encoding::hex_encode(public.as_bytes()),
                    "public_serialized": public.to_serialized(),
                }),
            );
        }
        roles.insert(
            Role::Pack.as_str().to_string(),
            json!({
                "suite": default_key.public().suite().to_string(),
                "key_id": default_key.key_id().to_string(),
                "public": unidpp_cli::encoding::hex_encode(default_key.public().as_bytes()),
                "public_serialized": default_key.public().to_serialized(),
                "suites": Value::Object(suites),
            }),
        );
        let mut m = serde_json::Map::new();
        m.insert("mode".into(), json!(self.mode.as_str()));
        m.insert("roles".into(), Value::Object(roles));
        if let Some(seed) = &self.dev_seed {
            m.insert("dev_seed".into(), json!(seed));
            m.insert(
                "warning".into(),
                json!("seeded-dev mode is for development only; production deployments must use env-key mode"),
            );
        }
        Value::Object(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_signatif::sign::{SignatureSlot, SigningDomain};

    #[test]
    fn dev_mode_is_deterministic_and_distinct_roles() {
        let a = Keyring::dev(Some("test-seed")).unwrap();
        let b = Keyring::dev(Some("test-seed")).unwrap();
        let c = Keyring::dev(Some("other-seed")).unwrap();
        assert_eq!(a.mode(), KeyringMode::SeededDev);
        assert_eq!(a.event_key().key_id(), b.event_key().key_id());
        assert_eq!(a.pack_key().key_id(), b.pack_key().key_id());
        assert_ne!(a.event_key().key_id(), c.event_key().key_id());
        assert_ne!(a.event_key().key_id(), a.pack_key().key_id());
        // The two roles use distinct seed material even when the dev
        // seed is the same — collision would defeat the multi-suite
        // anchor pinning a verifier performs.
        assert_ne!(
            a.event_key().public().as_bytes(),
            a.pack_key().public().as_bytes()
        );
    }

    #[test]
    fn empty_seed_falls_back_to_default() {
        let k = Keyring::dev(Some("")).unwrap();
        assert_eq!(k.dev_seed(), Some(DEFAULT_DEV_SEED));
        assert_eq!(k.mode(), KeyringMode::SeededDev);
    }

    #[test]
    fn env_mode_round_trip_and_minimum_length() {
        // Two distinct 32-byte hex seeds.
        let event = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee";
        let pack = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        let k = Keyring::from_env_seeds(event, pack).unwrap();
        assert_eq!(k.mode(), KeyringMode::EnvKey);
        assert!(k.dev_seed().is_none());
        // The raw seed is hashed into the signing scalar by
        // KeyPair::seeded, so the public key is derived material — not
        // the seed itself — but deterministic per seed.
        let event_hex = k.public_hex(Role::Event);
        assert_eq!(event_hex.len(), 64);
        assert_ne!(event_hex, event);
        let again = Keyring::from_env_seeds(event, pack).unwrap();
        assert_eq!(again.public_hex(Role::Event), event_hex);
        // Suite mapping: event → ed25519, pack → ecdsa-p256.
        assert_eq!(k.public(Role::Event).suite(), Suite::Ed25519);
        assert_eq!(k.public(Role::Pack).suite(), Suite::EcdsaP256);
        // Pack public matches the seed-derivation line.
        let re_derived = KeyPair::seeded(
            Suite::EcdsaP256,
            &unidpp_cli::encoding::hex_decode(pack).unwrap(),
        )
        .unwrap();
        assert_eq!(k.public(Role::Pack), re_derived.public());
    }

    #[test]
    fn env_mode_rejects_short_and_bad_hex() {
        let short = "deadbeef"; // 4 bytes
        let good = "00112233445566778899aabbccddeeff";
        assert!(Keyring::from_env_seeds(short, good).is_err());
        assert!(Keyring::from_env_seeds(good, short).is_err());
        assert!(Keyring::from_env_seeds("nonsense!!", good).is_err());
    }

    #[test]
    fn pack_seed_is_consistent_with_derivation() {
        let k = Keyring::dev(Some("deterministic")).unwrap();
        let from_seed = KeyPair::seeded(
            Suite::EcdsaP256,
            format!("unidpp-issuer/pack|{}", "deterministic").as_bytes(),
        )
        .unwrap();
        assert_eq!(k.pack_key().public(), from_seed.public());
        assert_eq!(k.pack_seed(), b"unidpp-issuer/pack|deterministic");
    }

    #[test]
    fn pack_suites_parse_validates_computation_and_carrier() {
        let d = PackSuites::default();
        assert_eq!(d.as_slice(), &[Suite::EcdsaP256]);
        assert_eq!(d.tokens(), vec!["ecdsa-p256"]);

        let sm2 = PackSuites::parse("sm2").unwrap();
        assert_eq!(sm2.as_slice(), &[Suite::Sm2]);
        let co = PackSuites::parse("ecdsa-p256, sm2").unwrap();
        assert_eq!(co.as_slice(), &[Suite::EcdsaP256, Suite::Sm2]);
        assert_eq!(co.default_suite(), Suite::EcdsaP256);
        // Duplicates collapse; order preserved.
        let dedup = PackSuites::parse("sm2,sm2,ecdsa-p256").unwrap();
        assert_eq!(dedup.as_slice(), &[Suite::Sm2, Suite::EcdsaP256]);
        assert_eq!(dedup.default_suite(), Suite::Sm2);
        // Case and separator tolerance.
        assert_eq!(
            PackSuites::parse("SM2 ecdsa-p256").unwrap().as_slice(),
            &[Suite::Sm2, Suite::EcdsaP256]
        );

        // Refusals: unknown token, no carrier slot, no computation,
        // empty list.
        assert!(PackSuites::parse("wat").is_err());
        assert!(PackSuites::parse("ed25519").is_err()); // no carrier slot
        assert!(PackSuites::parse("ml-dsa-87").is_err()); // framed-only
        assert!(PackSuites::parse(", ,").is_err());
    }

    #[test]
    fn multi_suite_keyring_derives_one_key_per_suite() {
        let suites = PackSuites::parse("ecdsa-p256,sm2,ml-dsa-65").unwrap();
        let k = Keyring::with_pack_suites(Some("seed-x"), &suites).unwrap();
        let keys = k.pack_keys();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].suite(), Suite::EcdsaP256);
        assert_eq!(keys[1].suite(), Suite::Sm2);
        assert_eq!(keys[2].suite(), Suite::MlDsa65);
        // Suite-separated seeds: distinct key ids across suites.
        let ids: Vec<_> = keys.iter().map(|key| key.key_id().to_string()).collect();
        let set: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(set.len(), 3);
        // The anchors line up with the CLI's minting convention: the
        // same base seed signs and verifies.
        let payload = unidpp_cli::packfile::signing_body(&sample_tier_a()).unwrap();
        for key in keys {
            let slot = SignatureSlot::sign(key, SigningDomain::ArtifactEvent, &payload).unwrap();
            slot.verify(SigningDomain::ArtifactEvent, &payload, key.public())
                .unwrap();
        }
        // The legacy default-role accessors expose the first suite.
        assert_eq!(k.pack_key().suite(), suites.default_suite());
        assert_eq!(k.pack_anchors().len(), 3);
    }

    #[test]
    fn keyring_json_lists_every_pack_suite_anchor() {
        let suites = PackSuites::parse("ecdsa-p256,sm2").unwrap();
        let k = Keyring::with_pack_suites(Some("seed-y"), &suites).unwrap();
        let v = k.to_json();
        // Back-compat top-level fields: the default suite.
        assert_eq!(v["roles"]["pack"]["suite"], "ecdsa-p256");
        // The co-signature set: one entry per configured suite.
        let suites_json = &v["roles"]["pack"]["suites"];
        assert_eq!(
            suites_json["ecdsa-p256"]["key_id"],
            k.pack_keys()[0].key_id().to_string()
        );
        assert_eq!(
            suites_json["sm2"]["key_id"],
            k.pack_keys()[1].key_id().to_string()
        );
        assert!(suites_json["sm2"]["public"].as_str().unwrap().len() == 130);
    }

    fn sample_tier_a() -> unidpp_tier_a::TierAPayload {
        let id = unidpp_model::PassportId::new("urn:unidpp:passport:keyring-test")
            .expect("well-formed test id");
        let mut log = unidpp_event::EventLog::new(id);
        let event = unidpp_event::TypedEvent::new(
            0,
            unidpp_model::Timestamp::from_secs(1_800_000_000),
            "issuing authority",
            "eo-t",
            unidpp_event::EventType::Issuance,
            crate::events::default_payload(unidpp_event::EventType::Issuance).unwrap(),
            unidpp_model::TrustMarker::Attested,
        )
        .unwrap();
        log.append(event, None, None).unwrap();
        unidpp_tier_a::TierAPayload::from_log(
            &log,
            unidpp_model::ProductIdentifier::parse("gtin:4006381333931").unwrap(),
            "https://resolver.unidpp.org/r/test-1",
            "eo-t",
            unidpp_model::Interval::starting(unidpp_model::Timestamp::from_secs(1_800_000_000)),
            vec![],
        )
    }

    #[test]
    fn to_json_includes_roles_and_warning_in_dev() {
        let k = Keyring::dev(Some("j")).unwrap();
        let v = k.to_json();
        assert_eq!(v["mode"], "seeded-dev");
        assert_eq!(v["roles"]["event"]["suite"], "ed25519");
        assert_eq!(v["roles"]["pack"]["suite"], "ecdsa-p256");
        assert!(v["roles"]["event"]["key_id"]
            .as_str()
            .unwrap()
            .starts_with("k-"));
        assert!(v["warning"].as_str().unwrap().contains("seeded-dev"));
    }
}
