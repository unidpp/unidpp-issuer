//! UniDPP passport lifecycle issuer service (crate `unidpp-issuer`).
//!
//! Part of UniDPP (github.com/unidpp) — part of UniDPP
//! `10-remaining-tasks-definitive.md` item 10: the service that lets an
//! operator *run* a passport lifecycle end-to-end. The libraries prove
//! the model; this service proves the system:
//!
//! - [`api`] — the HTTP surface (axum over tokio): create passports
//!   (identity, type ref, config vector, capability class → passport id
//!   + empty log), append typed events (server-signed with the keyring's
//!     Ed25519 key → `TrustMarker::Attested`, illegal status transitions
//!     rejected per invariant I6), mint Tier-A offline packs with real
//!     multi-suite signatures and QR budget enforcement, render the core +
//!     manifest + log-head view, and run the full-pipeline verdict;
//! - [`keyring`] — server key material: deterministic seeded dev mode
//!   and env-key prod mode (real crypto via `unidpp-signatif`:
//!   Ed25519 for events, RFC 6979 ECDSA-P256 for Tier-A packs — the
//!   carrier-table deviation documented in `unidpp-signatif::sign`);
//! - [`store`] — passports, admin registrations, and the append-only
//!   audit log persisted as a JSONL journal and replayed on start;
//! - [`registry`] — admin forwarding of profile registrations and
//!   applicability bindings to a `unidpp-registry` instance over HTTP,
//!   with local fixtures when no registry is configured or reachable;
//! - [`http`] — the minimal async `http://` client shared by the
//!   registry forwarder and the integration tests (house pattern).
//!
//! Server conventions mirror `unidpp-registry` (itself mirroring
//! `unidpp-resolver`): every response is as-of stamped (`x-as-of`
//! header plus an `as_of` body field); not-found responses are
//! no-information (identical bytes for unknown passports, I12); all
//! mutations are audited and journaled; mutations require a Bearer
//! token when `UNIDPP_ISSUER_ADMIN_TOKEN` is set (open in dev mode).

// Handlers and parse helpers return `Result<_, Response>` with the
// ready-made error response by value — the idiomatic axum pattern;
// boxing the error would complicate every call site for no gain.
#![allow(clippy::result_large_err)]

pub mod api;
pub mod events;
pub mod http;
pub mod keyring;
pub mod registry;
pub mod store;

pub use api::{run, Config, TestServer};
pub use keyring::{Keyring, KeyringMode};
pub use registry::{RegistryClient, RegistryMode, RegistryOutcome};
pub use store::{Op, PassportRecord, Store, StoreError};
