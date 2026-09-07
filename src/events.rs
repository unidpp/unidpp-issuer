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

use serde_json::Value;
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
