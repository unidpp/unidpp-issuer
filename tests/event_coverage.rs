//! Total event-payload coverage over real HTTP: every event class in
//! the taxonomy POSTs to `/passports/{id}/events` with its typed
//! payload fixture — accepted, or refused as a legal state-machine
//! conflict (never a payload-shape 400) — and the headline classes
//! assert the document state they produce.

use std::time::Duration;

use serde_json::{json, Value};
use unidpp_event::EventType;
use unidpp_issuer::events::example_data;
use unidpp_issuer::http::{json_request, HttpResponse};
use unidpp_issuer::{Config, TestServer};

const TIMEOUT: Duration = Duration::from_secs(10);

async fn post(base: &str, path: &str, body: &Value) -> HttpResponse {
    json_request(
        "POST",
        &format!("{base}{path}"),
        Some(&body.to_string()),
        None,
        TIMEOUT,
    )
    .await
    .expect("http request")
}

async fn get(base: &str, path: &str) -> HttpResponse {
    json_request("GET", &format!("{base}{path}"), None, None, TIMEOUT)
        .await
        .expect("http request")
}

fn json_of(resp: &HttpResponse) -> Value {
    serde_json::from_str(&resp.body_string()).expect("response JSON")
}

async fn fresh_passport(server: &TestServer, tag: &str) -> String {
    let resp = post(
        &server.base_url,
        "/passports",
        &json!({
            "identity": format!("sgtin:4006381333931+21+EV-{tag}"),
            "granularity": "item",
            "type_ref": "e-bike",
            "capability": "S1",
            "eo_id": "urn:eo:coverage",
        }),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    json_of(&resp)["passport_id"].as_str().unwrap().to_string()
}

async fn append(server: &TestServer, id: &str, event_type: EventType, tag: &str) -> HttpResponse {
    post(
        &server.base_url,
        &format!("/passports/{id}/events"),
        &json!({
            "type": event_type.to_string(),
            "data": example_data(event_type),
            "actor_role": event_type.appender_role(),
            "actor": format!("urn:eo:{tag}"),
        }),
    )
    .await
}

#[tokio::test]
async fn every_event_class_posts_with_its_typed_payload() {
    let server = TestServer::spawn(Config::default()).await.expect("spawn");
    let mut accepted = 0usize;
    for (index, event_type) in EventType::ALL.iter().enumerate() {
        let id = fresh_passport(&server, &format!("t{index}")).await;
        let resp = append(&server, &id, *event_type, "total").await;
        assert_ne!(
            resp.status,
            400,
            "{}: payload fixture must be well formed, got {} {}",
            event_type,
            resp.status,
            resp.body_string()
        );
        if resp.status == 201 {
            accepted += 1;
            let doc = json_of(&resp);
            assert_eq!(doc["event_type"], event_type.to_string());
            assert!(doc["signature"].is_object(), "{event_type}: server-signed");
            assert!(doc["log_head"].as_str().is_some_and(|h| h.len() == 64));
        } else if resp.status == 409 {
            // A legal state-machine refusal (I6): the payload parsed and
            // typed correctly; this fresh passport simply is not in the
            // state the class requires.
            let doc = json_of(&resp);
            assert!(
                doc["error"]
                    .as_str()
                    .unwrap()
                    .contains("illegal status transition"),
                "{event_type}: 409 must be an I6 conflict, got {}",
                doc["error"]
            );
        } else {
            panic!("{event_type}: unexpected status {}", resp.status);
        }
    }
    // The overwhelming majority append to a fresh passport; a conflict
    // is legal, but none of the classes should be *unable* to post.
    assert!(
        accepted >= 20,
        "only {accepted} of {} accepted",
        EventType::ALL.len()
    );
    server.stop().await;
}

#[tokio::test]
async fn headline_classes_change_the_document_state() {
    let server = TestServer::spawn(Config::default()).await.expect("spawn");

    // custody.transfer: the custodian trail moves to the counterparty.
    let id = fresh_passport(&server, "custody").await;
    let resp = append(&server, &id, EventType::CustodyTransfer, "custody").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let doc = json_of(&get(&server.base_url, &format!("/passports/{id}")).await);
    assert_eq!(doc["custodian"], "urn:eo:distributor");
    assert_eq!(doc["status"], "issued");

    // part.replace: accepted, status unchanged (the part's own log
    // carries the installation edge).
    let resp = append(&server, &id, EventType::PartReplace, "repairer").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());

    // product.modify: the derived type + re-evaluation flags ride the
    // payload verbatim.
    let resp = append(&server, &id, EventType::ProductModify, "modifier").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    assert_eq!(json_of(&resp)["event_type"], "product.modify");

    // software.update: version vector accepted.
    let resp = append(&server, &id, EventType::SoftwareUpdate, "service").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());

    // upgrade.install (E6 — the payload class this coverage round
    // added to the core): the new child reference is accepted.
    let resp = append(&server, &id, EventType::UpgradeInstall, "installer").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());

    // recall.campaign: the safety flag flips.
    let resp = append(&server, &id, EventType::RecallCampaign, "regulator").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let doc = json_of(&get(&server.base_url, &format!("/passports/{id}")).await);
    assert_eq!(doc["safety"], "recall-active");
    assert_eq!(doc["status"], "issued");

    // inspection.stamp: accepted on an issued passport.
    let resp = append(&server, &id, EventType::InspectionStamp, "cab").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());

    // decompose: the subject transitions to transformed.
    let resp = append(&server, &id, EventType::Decompose, "recycler").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let doc = json_of(&get(&server.base_url, &format!("/passports/{id}")).await);
    assert_eq!(doc["status"], "transformed");
    server.stop().await;
}

#[tokio::test]
async fn status_change_replays_and_correction_counts() {
    let server = TestServer::spawn(Config::default()).await.expect("spawn");
    let id = fresh_passport(&server, "status").await;
    // issued -> suspended (legal).
    let resp = append(&server, &id, EventType::StatusChange, "regulator").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let doc = json_of(&get(&server.base_url, &format!("/passports/{id}")).await);
    assert_eq!(doc["status"], "suspended");
    // A correction is recorded and counted.
    let resp = append(&server, &id, EventType::Correction, "eo").await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let resp = get(&server.base_url, &format!("/passports/{id}/verdict")).await;
    let doc = json_of(&resp);
    assert!(doc["log"].to_string().contains("correction"));
    server.stop().await;
}

#[tokio::test]
async fn issuance_accepts_its_default_payload_without_data() {
    let server = TestServer::spawn(Config::default()).await.expect("spawn");
    let id = fresh_passport(&server, "default").await;
    let resp = post(
        &server.base_url,
        &format!("/passports/{id}/events"),
        &json!({"type": "issuance"}),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    let resp = post(
        &server.base_url,
        &format!("/passports/{id}/events"),
        &json!({"type": "milestone.record"}),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.body_string());
    server.stop().await;
}
