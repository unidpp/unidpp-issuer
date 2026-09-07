//! Issuer store: passports keyed by passport id, locally registered
//! profiles and applicability bindings (admin fixtures), and the
//! append-only audit log of every mutation. The optional JSONL journal
//! persists the audit log and is replayed on start — the log *is* the
//! storage (nothing is edited in place; event appends recompute the
//! hash chain deterministically because the service never salts
//! server-side events, mirroring the registry's I4 doctrine and the
//! CLI's owner-side salt-ceremony stance).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use unidpp_cli::passport::{EventSignature, Passport};
use unidpp_event::{SafetyFlag, SealedEvent, Status, TypedEvent};
use unidpp_model::{Hash, PassportId, Timestamp, TrustMarker};

/// The service-side passport record: the CLI-side document (identity,
/// capability class, validity, the authoritative event log and its
/// signatures — the exact `unidpp/passport@1` schema the `unidpp` binary
/// reads and writes) plus the issuance-time **config vector**: the
/// registered configuration references (profiles) this passport was
/// issued under.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PassportRecord {
    /// The passport document.
    pub document: Passport,
    /// The config vector: registered profile/configuration references
    /// bound at issuance (rendered in the manifest view and resolved in
    /// the verdict's coverage).
    pub config: Vec<String>,
}

impl PassportRecord {
    /// The passport id (key).
    pub fn passport_id(&self) -> &PassportId {
        &self.document.passport_id
    }
}

/// A locally registered profile (admin fixture; forwarded to the
/// registry when one is configured — see [`crate::registry`]). The
/// registry holds the authoritative 19135 lifecycle; this record is the
/// issuer-side view used for config-vector resolution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileRecord {
    /// Profile item id (registry item id when forwarded).
    pub profile_id: String,
    /// The 19135 name/definition slot.
    pub definition: String,
    /// Version of the profile definition.
    pub version: String,
    /// Register the item lives in (registry `register_id`).
    pub register_id: Option<String>,
    /// Optional jurisdiction axis (presentation aid).
    pub jurisdiction: Option<String>,
    /// Data-point references (`register/item[@version]`).
    pub data_points: Vec<String>,
    /// When this record was registered.
    pub registered_at: Timestamp,
}

/// A locally recorded applicability binding (profile ↔ product type),
/// mirroring the registry's binding shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BindingRecord {
    /// The profile item id.
    pub profile_id: String,
    /// The subject product-type reference.
    pub product_type: String,
    /// Pinned profile version, when given.
    pub profile_version: Option<String>,
    /// Effective window start.
    pub effective_from: Timestamp,
    /// Effective window end (`None` = open).
    pub effective_until: Option<Timestamp>,
    /// Whether the binding backdates legally.
    pub retroactive: bool,
    /// When this record was registered.
    pub registered_at: Timestamp,
}

impl BindingRecord {
    /// Whether the binding is in force at `at` (legal as-of semantics:
    /// a retroactive binding applies from `effective_from`, a
    /// non-retroactive one only from `registered_at`).
    pub fn applies_at(&self, at: Timestamp) -> bool {
        if at < self.effective_from {
            return false;
        }
        if let Some(until) = self.effective_until {
            if at > until {
                return false;
            }
        }
        if self.retroactive {
            true
        } else {
            at >= self.registered_at
        }
    }
}

/// An append-only issuer mutation. Serialised to/from the journal by
/// serde (no hand-rolled field mapping).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Op {
    /// Initial creation of a passport (empty log).
    CreatePassport {
        /// The record as issued.
        record: PassportRecord,
    },
    /// A typed event appended to a passport's log, with the server
    /// signature over its canonical body (when the append was signed).
    AppendEvent {
        /// Target passport id.
        passport_id: PassportId,
        /// The event as sealed (body + trust marker).
        event: TypedEvent,
        /// The server's signature record (`None` = unsigned append).
        signature: Option<EventSignature>,
    },
    /// An admin profile registration. `via` records where it landed
    /// (`registry`, `fixtures`, `unreachable: …`).
    RegisterProfile {
        /// The registered record.
        profile: ProfileRecord,
        /// Where the registration landed.
        via: String,
    },
    /// An admin applicability binding.
    BindApplicability {
        /// The recorded binding.
        binding: BindingRecord,
        /// Where the binding landed.
        via: String,
    },
}

/// One record in the append-only audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Sequence number (1-based, gap-free).
    pub seq: u64,
    /// When the mutation was recorded.
    pub recorded_at: Timestamp,
    /// The mutation.
    pub op: Op,
}

/// Store-level validation failures mapped by the API layer
/// (`NotFound` → no-information 404, `Conflict` → 409, `Invalid` → 400).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// No such passport (rendered as a no-information 404).
    NotFound,
    /// Semantic conflict: duplicate id, illegal status transition (I6),
    /// non-monotonic append.
    Conflict(String),
    /// Malformed input.
    Invalid(String),
}

/// What an append produced, for the response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendOutcome {
    /// Sequence number of the sealed event.
    pub seq: u64,
    /// The new log head commitment.
    pub head: Hash,
    /// Replayed status after the append.
    pub status: Status,
    /// Replayed safety flag after the append.
    pub safety: SafetyFlag,
    /// Trust marker carried by the event.
    pub trust: TrustMarker,
}

/// Replay a prefix of sealed events to (status, safety, custodian) —
/// the same transition semantics as `EventLog::current_status` /
/// `safety_flag` / `custodian`, but over any prefix so as-of views
/// reuse it (`EventLog` replays only the full log).
pub fn replay_state<'a, I>(sealed: I) -> (Status, SafetyFlag, Option<String>)
where
    I: IntoIterator<Item = &'a SealedEvent>,
{
    use unidpp_event::EventPayload;
    let mut status = Status::Issued;
    let mut recall = false;
    let mut security = false;
    let mut custodian: Option<String> = None;
    for sealed in sealed {
        match &sealed.event.payload {
            EventPayload::Issuance { .. } => status = Status::Issued,
            EventPayload::StatusChange { to, .. } => status = *to,
            EventPayload::Split {
                parent_consumed, ..
            } => {
                if *parent_consumed {
                    status = Status::Transformed;
                }
            }
            EventPayload::Decompose { .. } => status = Status::Transformed,
            EventPayload::EndOfWaste { .. } => status = Status::EndOfWaste,
            EventPayload::RecallCampaign { .. } => recall = true,
            EventPayload::FlagSecurity { .. } => security = true,
            EventPayload::CustodyTransfer { to, .. } => custodian = Some(to.clone()),
            _ => {}
        }
    }
    let safety = match (recall, security) {
        (false, false) => SafetyFlag::None,
        (true, false) => SafetyFlag::RecallActive,
        (false, true) => SafetyFlag::SecurityFlagged,
        (true, true) => SafetyFlag::RecallActive,
    };
    (status, safety, custodian)
}

/// The issuer store. See the module docs for the storage doctrine.
pub struct Store {
    passports: HashMap<PassportId, PassportRecord>,
    profiles: HashMap<String, ProfileRecord>,
    bindings: Vec<BindingRecord>,
    log: Vec<AuditRecord>,
    journal: Option<File>,
}

impl Store {
    /// Fresh store with an optional JSONL journal (opened for append;
    /// existing lines are replayed).
    pub fn open(journal: Option<&Path>) -> std::io::Result<Store> {
        let mut store = Store {
            passports: HashMap::new(),
            profiles: HashMap::new(),
            bindings: Vec::new(),
            log: Vec::new(),
            journal: None,
        };
        if let Some(path) = journal {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            if path.exists() {
                store.replay(path)?;
            }
            store.journal = Some(OpenOptions::new().create(true).append(true).open(path)?);
        }
        Ok(store)
    }

    fn replay(&mut self, path: &Path) -> std::io::Result<()> {
        let file = File::open(path)?;
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditRecord>(&line) {
                Ok(rec) => {
                    self.apply(&rec);
                    self.log.push(rec);
                }
                Err(e) => {
                    // A torn final line (crash mid-write) is tolerated;
                    // anything else is reported and skipped loudly.
                    eprintln!("unidpp-issuer: journal line {}: {e}", i + 1);
                }
            }
        }
        Ok(())
    }

    /// Append a record to the audit log (and journal), then apply it.
    fn record(&mut self, op: Op) -> std::io::Result<AuditRecord> {
        let rec = AuditRecord {
            seq: self.log.len() as u64 + 1,
            recorded_at: Timestamp::now(),
            op,
        };
        if let Some(j) = self.journal.as_mut() {
            let line = serde_json::to_string(&rec).expect("audit records are plain serde data");
            writeln!(j, "{line}")?;
        }
        self.apply(&rec);
        self.log.push(rec.clone());
        Ok(rec)
    }

    /// Pure state transition used by both live recording and journal
    /// replay.
    fn apply(&mut self, rec: &AuditRecord) {
        match &rec.op {
            Op::CreatePassport { record } => {
                self.passports
                    .insert(record.passport_id().clone(), record.clone());
            }
            Op::AppendEvent {
                passport_id,
                event,
                signature,
            } => {
                if let Some(record) = self.passports.get_mut(passport_id) {
                    // Deterministic unsalted re-seal: the same event
                    // always produces the same commitment chain.
                    let _ = record.document.log.append(event.clone(), None, None);
                    if let Some(sig) = signature {
                        record.document.event_signatures.push(sig.clone());
                    }
                }
            }
            Op::RegisterProfile { profile, .. } => {
                self.profiles
                    .insert(profile.profile_id.clone(), profile.clone());
            }
            Op::BindApplicability { binding, .. } => {
                self.bindings.push(binding.clone());
            }
        }
    }

    // -- reads ----------------------------------------------------------

    /// One passport record.
    pub fn passport(&self, id: &str) -> Option<&PassportRecord> {
        PassportId::new(id)
            .ok()
            .and_then(|pid| self.passports.get(&pid))
    }

    /// All passport records, sorted by passport id.
    pub fn passports(&self) -> Vec<&PassportRecord> {
        let mut out: Vec<&PassportRecord> = self.passports.values().collect();
        out.sort_by(|a, b| a.passport_id().as_str().cmp(b.passport_id().as_str()));
        out
    }

    /// One registered profile.
    pub fn profile(&self, profile_id: &str) -> Option<&ProfileRecord> {
        self.profiles.get(profile_id)
    }

    /// All registered profiles, sorted by id.
    pub fn profiles(&self) -> Vec<&ProfileRecord> {
        let mut out: Vec<&ProfileRecord> = self.profiles.values().collect();
        out.sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
        out
    }

    /// Bindings for a product-type subject.
    pub fn bindings_for(&self, product_type: &str) -> Vec<&BindingRecord> {
        self.bindings
            .iter()
            .filter(|b| b.product_type == product_type)
            .collect()
    }

    /// The append-only audit log (admin view, paged).
    pub fn log_json(&self, limit: usize, offset: usize) -> serde_json::Value {
        let total = self.log.len();
        let records: Vec<serde_json::Value> = self
            .log
            .iter()
            .skip(offset)
            .take(limit)
            .filter_map(|r| serde_json::to_value(r).ok())
            .collect();
        serde_json::json!({
            "total": total,
            "offset": offset,
            "records": records,
        })
    }

    /// Number of records in the audit log (tests and admin stats).
    pub fn log_len(&self) -> usize {
        self.log.len()
    }

    // -- mutations (validated, audited) ----------------------------------

    /// Create a passport. The passport id must be unused.
    pub fn create_passport(&mut self, record: PassportRecord) -> Result<AuditRecord, StoreError> {
        if self.passports.contains_key(record.passport_id()) {
            return Err(StoreError::Conflict(format!(
                "passport `{}` already exists",
                record.passport_id()
            )));
        }
        self.record(Op::CreatePassport { record })
            .map_err(|e| StoreError::Invalid(e.to_string()))
    }

    /// Append a typed event to a passport's log, enforcing the I6
    /// state machine against the log's *current* status (a StatusChange
    /// whose `from` does not match the replayed status is a semantic
    /// conflict even when `from -> to` is abstractly legal).
    pub fn append_event(
        &mut self,
        passport_id: &str,
        event: TypedEvent,
        signature: Option<EventSignature>,
    ) -> Result<(AuditRecord, AppendOutcome), StoreError> {
        let pid = PassportId::new(passport_id).map_err(|e| StoreError::Invalid(e.to_string()))?;
        let Some(record) = self.passports.get(&pid) else {
            return Err(StoreError::NotFound);
        };
        if let unidpp_event::EventPayload::StatusChange { from, to, .. } = &event.payload {
            let current = record.document.log.current_status();
            if *from != current {
                return Err(StoreError::Conflict(format!(
                    "illegal status transition {from} -> {to}: the log's current status is {current} (I6)"
                )));
            }
        }
        let trust = event.trust;
        let rec = self
            .record(Op::AppendEvent {
                passport_id: pid.clone(),
                event: event.clone(),
                signature: signature.clone(),
            })
            .map_err(|e| StoreError::Invalid(e.to_string()))?;
        let record = self
            .passports
            .get(&pid)
            .expect("passport exists after append");
        let log = &record.document.log;
        let outcome = AppendOutcome {
            seq: event.seq,
            head: log
                .head()
                .ok_or_else(|| StoreError::Conflict("log head missing after append".into()))?,
            status: log.current_status(),
            safety: log.safety_flag(),
            trust,
        };
        Ok((rec, outcome))
    }

    /// Register (or re-version) a profile. Re-registering the same
    /// version is a conflict; a new version replaces the record.
    pub fn register_profile(
        &mut self,
        profile: ProfileRecord,
        via: String,
    ) -> Result<AuditRecord, StoreError> {
        if let Some(existing) = self.profiles.get(&profile.profile_id) {
            if existing.version == profile.version {
                return Err(StoreError::Conflict(format!(
                    "profile `{}` version `{}` is already registered",
                    profile.profile_id, profile.version
                )));
            }
        }
        self.record(Op::RegisterProfile { profile, via })
            .map_err(|e| StoreError::Invalid(e.to_string()))
    }

    /// Record an applicability binding. The profile must be known
    /// locally (registered through this service).
    pub fn bind_applicability(
        &mut self,
        binding: BindingRecord,
        via: String,
    ) -> Result<AuditRecord, StoreError> {
        if !self.profiles.contains_key(&binding.profile_id) {
            return Err(StoreError::Invalid(format!(
                "profile `{}` is not registered",
                binding.profile_id
            )));
        }
        self.record(Op::BindApplicability { binding, via })
            .map_err(|e| StoreError::Invalid(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_cli::passport::MintOptions;
    use unidpp_event::{EventPayload, EventType};
    use unidpp_model::Granularity;

    fn record(id: &str, passport_id: Option<&str>) -> PassportRecord {
        let document = Passport::mint(MintOptions {
            id: id.to_string(),
            granularity: Some(Granularity::Item),
            type_ref: None,
            capability: "S1".to_string(),
            eo_id: Some("eo-test".to_string()),
            resolver_uri: None,
            passport_id: passport_id.map(str::to_string),
            valid_from: None,
            valid_to: None,
        })
        .unwrap();
        PassportRecord {
            document,
            config: vec!["urn:unidpp:profile:test".to_string()],
        }
    }

    fn custody(seq: u64, trust: TrustMarker) -> TypedEvent {
        TypedEvent::new(
            seq,
            Timestamp::from_secs(1_800_000_000 + seq as i64 * 60),
            "custodian",
            "eo-test",
            EventType::CustodyTransfer,
            EventPayload::CustodyTransfer {
                from: "a".into(),
                to: format!("holder-{seq}"),
                counterparty_signed: true,
            },
            trust,
        )
        .unwrap()
    }

    fn status_change(seq: u64, from: Status, to: Status) -> TypedEvent {
        TypedEvent::new(
            seq,
            Timestamp::from_secs(1_800_000_100 + seq as i64 * 60),
            "regulator",
            "reg-1",
            EventType::StatusChange,
            EventPayload::StatusChange {
                from,
                to,
                authority: "reg".into(),
            },
            TrustMarker::Attested,
        )
        .unwrap()
    }

    #[test]
    fn create_conflicts_on_duplicate_id() {
        let mut store = Store::open(None).unwrap();
        let rec = record("sgtin:4006381333931+21+SN7", Some("urn:unidpp:passport:t1"));
        store.create_passport(rec.clone()).unwrap();
        assert!(matches!(
            store.create_passport(rec),
            Err(StoreError::Conflict(_))
        ));
        // Same identity, distinct passport id: a re-issue, allowed (the
        // passport id is the service-side key).
        let other = record("sgtin:4006381333931+21+SN7", Some("urn:unidpp:passport:t2"));
        assert!(store.create_passport(other).is_ok());
        assert_eq!(store.passports().len(), 2);
        assert_eq!(store.log_len(), 2);
    }

    #[test]
    fn append_enforces_the_i6_state_machine() {
        let mut store = Store::open(None).unwrap();
        store
            .create_passport(record(
                "sgtin:4006381333931+21+SN7",
                Some("urn:unidpp:passport:t3"),
            ))
            .unwrap();
        let id = "urn:unidpp:passport:t3";
        // issued -> suspended: legal, `from` matches the replayed status.
        let (_, out) = store
            .append_event(
                id,
                status_change(0, Status::Issued, Status::Suspended),
                None,
            )
            .unwrap();
        assert_eq!(out.status, Status::Suspended);
        // The log is now suspended, but the event claims issued ->
        // suspended again: `from` no longer matches the replayed status.
        let err = store
            .append_event(
                id,
                status_change(1, Status::Issued, Status::Suspended),
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Conflict(ref m) if m.contains("I6")),
            "{err:?}"
        );
        // suspended -> invalidated: legal from the true current state.
        store
            .append_event(
                id,
                status_change(1, Status::Suspended, Status::Invalidated),
                None,
            )
            .unwrap();
        // Unknown passport: no-information not-found.
        assert!(matches!(
            store.append_event(
                "urn:unidpp:passport:nope",
                custody(0, TrustMarker::Attested),
                None
            ),
            Err(StoreError::NotFound)
        ));
    }

    #[test]
    fn append_records_signatures_and_replays_state() {
        let mut store = Store::open(None).unwrap();
        store
            .create_passport(record(
                "sgtin:4006381333931+21+SN7",
                Some("urn:unidpp:passport:t4"),
            ))
            .unwrap();
        let id = "urn:unidpp:passport:t4".to_string();
        let sig = EventSignature {
            seq: 0,
            suite: "ed25519".into(),
            key_id: "k-abc123".into(),
            signature: "00ff".into(),
        };
        let (_, out) = store
            .append_event(&id, custody(0, TrustMarker::Attested), Some(sig.clone()))
            .unwrap();
        assert_eq!(out.seq, 0);
        assert_eq!(out.trust, TrustMarker::Attested);
        assert_eq!(out.safety, SafetyFlag::None);
        let record = store.passport(&id).unwrap();
        assert_eq!(record.document.event_signatures, vec![sig]);
        assert_eq!(record.document.log.len(), 1);
        assert_eq!(record.document.log.head().unwrap(), out.head);
    }

    #[test]
    fn profiles_and_bindings_validate() {
        let mut store = Store::open(None).unwrap();
        let profile = ProfileRecord {
            profile_id: "urn:unidpp:profile:test".into(),
            definition: "test profile".into(),
            version: "1.0.0".into(),
            register_id: Some("unidpp-dev".into()),
            jurisdiction: Some("EU".into()),
            data_points: vec!["ferin:eu/battery-state".into()],
            registered_at: Timestamp::from_secs(1_800_000_000),
        };
        store
            .register_profile(profile.clone(), "fixtures".into())
            .unwrap();
        // Same version again: conflict.
        assert!(matches!(
            store.register_profile(profile.clone(), "fixtures".into()),
            Err(StoreError::Conflict(_))
        ));
        // New version: replaces.
        let mut v2 = profile.clone();
        v2.version = "2.0.0".into();
        store.register_profile(v2, "fixtures".into()).unwrap();
        assert_eq!(store.profiles().len(), 1);
        assert_eq!(
            store.profile("urn:unidpp:profile:test").unwrap().version,
            "2.0.0"
        );

        // Binding needs a known profile.
        let binding = BindingRecord {
            profile_id: "urn:unidpp:profile:test".into(),
            product_type: "battery-li-ion".into(),
            profile_version: None,
            effective_from: Timestamp::from_secs(1_700_000_000),
            effective_until: None,
            retroactive: true,
            registered_at: Timestamp::from_secs(1_800_000_000),
        };
        let mut unknown = binding.clone();
        unknown.profile_id = "urn:unidpp:profile:nope".into();
        assert!(matches!(
            store.bind_applicability(unknown, "fixtures".into()),
            Err(StoreError::Invalid(_))
        ));
        store
            .bind_applicability(binding.clone(), "registry".into())
            .unwrap();
        assert_eq!(store.bindings_for("battery-li-ion").len(), 1);
        assert!(binding.applies_at(Timestamp::from_secs(1_750_000_000)));
        let mut non_retro = binding.clone();
        non_retro.retroactive = false;
        assert!(!non_retro.applies_at(Timestamp::from_secs(1_750_000_000)));
        assert!(non_retro.applies_at(Timestamp::from_secs(1_800_000_500)));
    }

    #[test]
    fn journal_round_trip() {
        let dir = std::env::temp_dir().join(format!("unidpp-issuer-test-{}", std::process::id()));
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(&dir).unwrap();
        let id = "urn:unidpp:passport:t5";
        let (head, n_sigs) = {
            let mut store = Store::open(Some(&path)).unwrap();
            store
                .create_passport(record("sgtin:4006381333931+21+SN7", Some(id)))
                .unwrap();
            let sig = EventSignature {
                seq: 0,
                suite: "ed25519".into(),
                key_id: "k-feed".into(),
                signature: "aabb".into(),
            };
            store
                .append_event(id, custody(0, TrustMarker::Attested), Some(sig))
                .unwrap();
            store
                .append_event(id, custody(1, TrustMarker::Attested), None)
                .unwrap();
            let rec = store.passport(id).unwrap();
            (
                rec.document.log.head().unwrap(),
                rec.document.event_signatures.len(),
            )
        };
        let store = Store::open(Some(&path)).unwrap();
        assert_eq!(store.log_len(), 3);
        let rec = store.passport(id).unwrap();
        assert_eq!(rec.document.log.len(), 2);
        // Unsalted deterministic re-seal: replayed head matches.
        assert_eq!(rec.document.log.head().unwrap(), head);
        assert_eq!(rec.document.event_signatures.len(), n_sigs);
        assert!(rec.document.log.verify().is_ok());
        assert_eq!(rec.config, vec!["urn:unidpp:profile:test".to_string()]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn replay_state_matches_log_replay() {
        let mut store = Store::open(None).unwrap();
        store
            .create_passport(record(
                "sgtin:4006381333931+21+SN7",
                Some("urn:unidpp:passport:t6"),
            ))
            .unwrap();
        let id = "urn:unidpp:passport:t6".to_string();
        store
            .append_event(&id, custody(0, TrustMarker::Attested), None)
            .unwrap();
        store
            .append_event(
                &id,
                TypedEvent::new(
                    1,
                    Timestamp::from_secs(1_800_000_500),
                    "regulator",
                    "reg-1",
                    EventType::RecallCampaign,
                    EventPayload::RecallCampaign {
                        campaign: "R-9".into(),
                        predicate: unidpp_model::TriggerPredicate::Any,
                    },
                    TrustMarker::Attested,
                )
                .unwrap(),
                None,
            )
            .unwrap();
        let log = &store.passport(&id).unwrap().document.log;
        let (status, safety, custodian) = replay_state(log.sealed());
        assert_eq!(status, log.current_status());
        assert_eq!(safety, log.safety_flag());
        assert_eq!(custodian, log.custodian());
        // Prefix replay (as-of view) stops at the boundary.
        let prefix: Vec<&SealedEvent> = log.sealed().iter().take(1).collect();
        let (prefix_status, prefix_safety, _) = replay_state(prefix);
        assert_eq!(prefix_status, Status::Issued);
        assert_eq!(prefix_safety, SafetyFlag::None);
    }
}
