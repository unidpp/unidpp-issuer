//! Event-class dispatch: the canonical token for each [`EventType`]
//! variant and the default payload used when the request omits `--data`.
//!
//! The full taxonomy lives in `unidpp_event::EventType`; the issuer's
//! HTTP body accepts the canonical token (`custody.transfer`,
//! `install`, …) plus any casing/separator spelling
//! (`EventType::parse_token` normalises), and the data object either in
//! the externally-tagged wrapper form
//! (`{"Install": {…}}`) or the bare variant body
//! (`{"target": {…}}`). Type agreement between `--type` and the
//! payload's variant is enforced by [`unidpp_event::TypedEvent::new`].

use serde_json::{json, Value};
use unidpp_event::{EventPayload, EventType};

/// The externally-tagged JSON variant name each [`EventType`] deserialises
/// from / serialises to (mirrors the serde derive on `EventPayload`).
pub fn variant_name(t: EventType) -> &'static str {
    use EventType::*;
    match t {
        CustodyTransfer => "CustodyTransfer",
        PartReplace => "PartReplace",
        RepairPerform => "RepairPerform",
        ProductModify => "ProductModify",
        SoftwareUpdate => "SoftwareUpdate",
        UpgradeInstall => "UpgradeInstall",
        RefurbishRemanufacture => "RefurbishRemanufacture",
        ConsumableReplace => "ConsumableReplace",
        RecallCampaign => "RecallCampaign",
        Correction => "Correction",
        StatusChange => "StatusChange",
        FlagSecurity => "FlagSecurity",
        Decompose => "Decompose",
        InspectionStamp => "InspectionStamp",
        MilestoneRecord => "MilestoneRecord",
        Split => "Split",
        Combine => "Combine",
        EndOfWaste => "EndOfWaste",
        Install => "Install",
        Uninstall => "Uninstall",
        Issuance => "Issuance",
        EdgeVisibilityChange => "EdgeVisibilityChange",
        EscrowDisclosure => "EscrowDisclosure",
    }
}

/// The payload used when the request omits `--data`: only the classes
/// whose payloads have no operator-supplied content.
pub fn default_payload(t: EventType) -> Option<EventPayload> {
    match t {
        EventType::Issuance => Some(EventPayload::Issuance {
            derived: false,
            inputs: vec![],
        }),
        EventType::MilestoneRecord => Some(EventPayload::MilestoneRecord {
            counters: std::collections::BTreeMap::new(),
        }),
        _ => None,
    }
}

/// A well-formed example `--data` body for every [`EventType`] — the
/// fixture table behind the total coverage tests (every event class
/// the issuer accepts has a payload schema, demonstrated, not merely
/// declared). The fixtures are the wire shape operators POST: bare
/// variant bodies, exactly as `payload_from_data` wraps them.
pub fn example_data(t: EventType) -> Value {
    use EventType::*;
    let hash = "6162630000000000000000000000000000000000000000000000000000000000";
    let qty = |amount: &str| json!({"amount": amount, "unit": {"uom": "g", "registry_uri": "urn:unitsml:uom:g"}});
    match t {
        Issuance => json!({"derived": false, "inputs": []}),
        CustodyTransfer => json!({
            "from": "urn:eo:manufacturer",
            "to": "urn:eo:distributor",
            "counterparty_signed": true,
        }),
        Split => json!({
            "carve_outs": [
                {"child": "urn:unidpp:passport:split-child-1", "quantity": qty("40")},
                {"child": "urn:unidpp:passport:split-child-2", "quantity": qty("60")},
            ],
            "remainder": qty("0"),
            "parent_consumed": true,
        }),
        Combine => json!({
            "inputs": [{
                "input": "urn:unidpp:passport:combine-input-1",
                "quantity": qty("100"),
                "as_of_state_hash": hash,
            }],
            "output_quantity": qty("95"),
            "loss": qty("5"),
        }),
        EndOfWaste => json!({
            "evidence_ref": "urn:evidence:end-of-waste-1",
            "outputs": [{"child": "urn:unidpp:passport:eow-output-1", "quantity": qty("500")}],
        }),
        Decompose => json!({
            "outputs": [
                {"child": "urn:unidpp:passport:decompose-battery", "quantity": qty("500")},
                {"child": "urn:unidpp:passport:decompose-frame", "quantity": qty("15000")},
            ],
            "accredited_for_claims": true,
        }),
        Install => json!({
            "target": {"Open": {
                "link_type": "installation",
                "other": "urn:unidpp:passport:parent-e-bike",
                "direction": "incoming",
                "interval": {"from": "2026-09-07T00:00:00Z", "to": null},
                "binding": null,
            }}
        }),
        Uninstall => json!({
            "link": {
                "link_type": "installation",
                "other": "urn:unidpp:passport:parent-e-bike",
                "direction": "incoming",
                "interval": {"from": "2026-09-07T00:00:00Z", "to": null},
                "binding": null,
            },
            "outcome": "harvested",
        }),
        PartReplace => json!({
            "removed": "urn:unidpp:passport:old-battery",
            "added": "urn:unidpp:passport:new-battery",
            "like_for_like": true,
        }),
        ConsumableReplace => json!({
            "removed": "urn:unidpp:passport:worn-brake-pads",
            "added": "urn:unidpp:passport:new-brake-pads",
        }),
        UpgradeInstall => json!({
            "added": "urn:unidpp:passport:cargo-rack-1",
        }),
        RepairPerform => json!({
            "authorization": "authorized",
            "consumed_parts": ["urn:unidpp:passport:consumed-part-1"],
        }),
        ProductModify => json!({
            "description": "cargo rack installed",
            "derived_type": Some("e-bike-cargo-variant"),
            "reevaluation_required": true,
        }),
        SoftwareUpdate => json!({
            "versions": {"firmware": "2.1.0", "display": "1.0.4"},
            "unlocked_features": ["cargo-mode"],
        }),
        RefurbishRemanufacture => json!({
            "remanufacture": false,
            "condition_grade": "A",
        }),
        RecallCampaign => json!({
            "campaign": "RC-2026-014",
            "predicate": {"FactEq": {"path": "battery.cell.family", "value": {"t": "Str", "v": "X7"}}},
        }),
        Correction => json!({
            "field": "mass",
            "prior_value": "12.5",
            "new_value": "12.4",
            "reason": "measurement correction (CAB report 2026-09)",
        }),
        StatusChange => json!({
            "from": "issued",
            "to": "suspended",
            "authority": "urn:eo:market-surveillance",
        }),
        FlagSecurity => json!({"kind": "theft", "reference": "urn:police:report-2026-118"}),
        InspectionStamp => json!({
            "stamp": {
                "attester": "urn:eo:cab-1",
                "subject": "urn:unidpp:passport:stamp-subject",
                "subject_state_commitment": hash,
                "lens": "urn:unidpp:profile:eu-espr-battery-v3",
                "lens_version": "3.0",
                "mode": "live",
                "verdict_summary": Some("conformant"),
                "coverage_report": null,
                "log_anchored_at": "2026-09-07T00:00:00Z",
                "quantity_context": null,
            }
        }),
        MilestoneRecord => json!({"counters": {"charge_cycles": "1200"}}),
        EdgeVisibilityChange => json!({
            "link_to": "urn:unidpp:passport:linked-parent",
            "new_visibility": "public",
            "ceremony": null,
        }),
        EscrowDisclosure => json!({
            "commitment_seq": 1,
            "disclosed_to": "urn:eo:court",
            "ceremony": "court",
        }),
    }
}

/// Whether `value` is an already-wrapped
/// `{"<VariantName>": {…}}` payload.
fn looks_wrapped(value: &Value) -> bool {
    value
        .as_object()
        .map(|m| {
            m.len() == 1
                && EventType::ALL
                    .iter()
                    .any(|t| m.contains_key(variant_name(*t)))
        })
        .unwrap_or(false)
}

/// Build the typed payload from `--data`: either an already-wrapped
/// single-variant object or the bare variant body, wrapped using
/// `--type`. Type agreement is enforced by
/// [`unidpp_event::TypedEvent::new`] at append time; here we only check
/// that what was supplied parses as `EventPayload`.
pub fn payload_from_data(t: EventType, data: &Value) -> Result<EventPayload, String> {
    let wrapped = if looks_wrapped(data) {
        data.clone()
    } else {
        let mut m = serde_json::Map::new();
        m.insert(variant_name(t).to_string(), data.clone());
        Value::Object(m)
    };
    let payload: EventPayload = serde_json::from_value(wrapped)
        .map_err(|e| format!("--data does not match the `{}` payload shape: {e}", t))?;
    if payload.event_type() != t {
        return Err(format!(
            "--data carries a {} payload but --type is {t}",
            payload.event_type()
        ));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn variant_names_are_unique_and_total() {
        let mut seen = std::collections::BTreeSet::new();
        for t in EventType::ALL {
            let name = variant_name(*t);
            assert!(!name.is_empty());
            assert!(seen.insert(name), "duplicate variant name `{name}`");
        }
        assert_eq!(seen.len(), EventType::ALL.len());
    }

    #[test]
    fn every_event_type_has_a_well_formed_payload_fixture() {
        // The fixture table is total: every variant of the taxonomy
        // parses as its payload, through the same path the HTTP body
        // takes.
        for t in EventType::ALL {
            let payload = payload_from_data(*t, &example_data(*t))
                .unwrap_or_else(|e| panic!("{} fixture does not parse: {e}", t));
            assert_eq!(payload.event_type(), *t);
            // And the fixture survives a serde round trip unchanged.
            let json = serde_json::to_value(&payload).unwrap();
            let back: EventPayload = serde_json::from_value(json).unwrap();
            assert_eq!(back, payload);
        }
    }

    #[test]
    fn default_payloads_round_trip_through_the_wrapped_form() {
        for t in [EventType::Issuance, EventType::MilestoneRecord] {
            let payload = default_payload(t).unwrap();
            let json = serde_json::to_value(&payload).unwrap();
            let back = payload_from_data(t, &json).unwrap();
            assert_eq!(back, payload);
        }
        assert!(default_payload(EventType::CustodyTransfer).is_none());
        assert!(default_payload(EventType::Correction).is_none());
    }

    #[test]
    fn bare_and_wrapped_payload_forms_agree() {
        let target = json!({"from": "mfg", "to": "dist", "counterparty_signed": true});
        let bare = payload_from_data(EventType::CustodyTransfer, &target).unwrap();
        let wrapped = payload_from_data(
            EventType::CustodyTransfer,
            &json!({"CustodyTransfer": target}),
        )
        .unwrap();
        assert_eq!(bare, wrapped);
    }

    #[test]
    fn mismatched_type_and_bad_shapes_are_errors() {
        // A wrapped payload for a different variant than the type token.
        let err = payload_from_data(
            EventType::CustodyTransfer,
            &json!({"Issuance": {"derived": false, "inputs": []}}),
        )
        .unwrap_err();
        assert!(err.contains("payload but"), "{err}");
        // Bare body missing required fields of the named variant.
        assert!(payload_from_data(EventType::Correction, &json!({"field": "f"})).is_err());
        // Non-object bodies cannot be wrapped.
        assert!(payload_from_data(EventType::Issuance, &json!("nope")).is_err());
        assert!(payload_from_data(EventType::Issuance, &json!([])).is_err());
    }
}
