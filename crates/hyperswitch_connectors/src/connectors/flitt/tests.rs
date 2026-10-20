//! Connector-level tests of Flitt: callbacks through the webhook trait, error
//! answers per flow, and the connector's declared capabilities.

use std::{future::Future, task::Poll};

use api_models::{
    payments::PaymentIdType,
    webhooks::{IncomingWebhookEvent, ObjectReferenceId},
};
use hyperswitch_interfaces::webhooks::{IncomingWebhook as _, IncomingWebhookRequestDetails};

use super::*;

const STATUS_APPROVED: &str = include_str!("test_data/status_approved_v2.json");
const STATUS_HOLD: &str = include_str!("test_data/status_hold_v2.json");

/// Runs a future that never waits (the webhook checks do no I/O).
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the future waited"),
    }
}

fn key(value: &str) -> Secret<String> {
    Secret::new(value.to_string())
}

/// The decoded order of a test-data answer.
fn order_payload(answer: &str) -> serde_json::Value {
    protocol::read_answer(answer.as_bytes(), &key("test"))
        .unwrap()
        .unwrap()
}

/// A callback as Flitt sends it for a protocol 2.0 order: the envelope,
/// without the `response` wrapper of API answers.
fn enveloped_callback(order: &serde_json::Value, payment_key: &str) -> Vec<u8> {
    let request = protocol::encode_request(&key(payment_key), order).unwrap();
    serde_json::to_vec(&serde_json::json!({
        "version": "2.0",
        "data": request.request.data,
        "signature": request.request.signature,
        "response_status": "success"
    }))
    .unwrap()
}

fn flat_callback(order: &serde_json::Value, payment_key: &str) -> Vec<u8> {
    let mut flat = order.as_object().unwrap().clone();
    let signature = protocol::sign_flat(&key(payment_key), &flat);
    flat.insert(
        "signature".to_string(),
        serde_json::Value::String(signature),
    );
    serde_json::to_vec(&flat).unwrap()
}

fn callback<'a>(
    headers: &'a actix_web::http::header::HeaderMap,
    body: &'a [u8],
) -> IncomingWebhookRequestDetails<'a> {
    IncomingWebhookRequestDetails {
        method: http::Method::POST,
        uri: http::Uri::from_static("/webhooks/merchant_1/mca_1"),
        headers,
        body,
        query_params: String::new(),
    }
}

fn account(
    payment_key: &str,
    merchant_id: &str,
) -> common_utils::crypto::Encryptable<Secret<serde_json::Value>> {
    common_utils::crypto::Encryptable::new(
        Secret::new(serde_json::json!({
            "auth_type": "BodyKey",
            "api_key": payment_key,
            "key1": merchant_id
        })),
        Secret::new(Vec::new()),
    )
}

fn verified(body: &[u8], payment_key: &str, merchant_id: &str) -> bool {
    let headers = actix_web::http::header::HeaderMap::new();
    let request = callback(&headers, body);
    let merchant = common_utils::id_type::MerchantId::default();
    ready(Flitt::new().verify_webhook_source(
        &request,
        &merchant,
        None,
        account(payment_key, merchant_id),
        "flitt",
    ))
    .unwrap()
}

#[test]
fn a_signed_callback_of_this_merchant_is_verified() {
    let approved = order_payload(STATUS_APPROVED);
    assert!(verified(
        &enveloped_callback(&approved, "test"),
        "test",
        "1549901"
    ));
    // Another account's key or merchant id: not this account's callback.
    assert!(!verified(
        &enveloped_callback(&approved, "test"),
        "other",
        "1549901"
    ));
    assert!(!verified(
        &enveloped_callback(&approved, "test"),
        "test",
        "1549902"
    ));
    // A flat callback is never trusted as it is, even correctly signed.
    assert!(!verified(
        &flat_callback(&approved, "test"),
        "test",
        "1549901"
    ));
    // Noise.
    assert!(!verified(b"{}", "test", "1549901"));
}

#[test]
fn the_callback_names_the_order_and_its_state() {
    let headers = actix_web::http::header::HeaderMap::new();
    let approved = order_payload(STATUS_APPROVED);
    let order_id = approved["order_id"].as_str().unwrap().to_string();
    for body in [
        enveloped_callback(&approved, "test"),
        flat_callback(&approved, "test"),
        serde_json::to_vec(&serde_json::json!({ "response": approved.clone() })).unwrap(),
    ] {
        let request = callback(&headers, &body);
        match Flitt::new()
            .get_webhook_object_reference_id(&request)
            .unwrap()
        {
            ObjectReferenceId::PaymentId(PaymentIdType::ConnectorTransactionId(id)) => {
                assert_eq!(id, order_id)
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            Flitt::new().get_webhook_event_type(&request, None).unwrap(),
            IncomingWebhookEvent::PaymentIntentSuccess
        );
    }
    let hold = enveloped_callback(&order_payload(STATUS_HOLD), "test");
    assert_eq!(
        Flitt::new()
            .get_webhook_event_type(&callback(&headers, &hold), None)
            .unwrap(),
        IncomingWebhookEvent::PaymentIntentAuthorizationSuccess
    );
    for noise in [&b"not json"[..], &b"{}"[..]] {
        assert!(Flitt::new()
            .get_webhook_object_reference_id(&callback(&headers, noise))
            .is_err());
    }
}

/// A verified callback reaches PSync's `handle_response` as the resource
/// object; it must read there exactly like a status answer, signature
/// included.
#[test]
fn the_resource_object_reads_like_a_signed_status_answer() {
    let headers = actix_web::http::header::HeaderMap::new();
    let approved = order_payload(STATUS_APPROVED);
    let body = enveloped_callback(&approved, "test");
    let resource = Flitt::new()
        .get_webhook_resource_object(&callback(&headers, &body))
        .unwrap();
    let bytes = serde_json::to_vec(&resource).unwrap();
    let read = protocol::read_answer(&bytes, &key("test"))
        .unwrap()
        .unwrap();
    assert_eq!(read, approved);
    // With another key the same object is refused.
    assert!(protocol::read_answer(&bytes, &key("other")).is_err());
}

#[test]
fn every_callback_is_acknowledged_with_200() {
    let headers = actix_web::http::header::HeaderMap::new();
    let request = callback(&headers, b"{}");
    assert!(matches!(
        Flitt::new().get_webhook_api_response(&request, None, None),
        Ok(hyperswitch_domain_models::api::WebhookResponse::StatusOk)
    ));
    // Unverified callbacks still run a status request instead of failing.
    assert!(!Flitt::new().is_webhook_source_verification_mandatory());
}

fn answer(status_code: u16, body: &'static [u8]) -> Response {
    Response {
        headers: None,
        response: bytes::Bytes::from_static(body),
        status_code,
    }
}

#[test]
fn a_refused_create_order_leaves_the_payment_payable() {
    let refused = <Flitt as ConnectorIntegration<
        Authorize,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    >>::get_error_response(
        Flitt::new(), answer(403, b"<html>blocked</html>"), None
    )
    .unwrap();
    assert_eq!(refused.status_code, 403);
    assert_eq!(
        refused.attempt_status,
        Some(enums::AttemptStatus::PaymentMethodAwaited)
    );
    let outage = <Flitt as ConnectorIntegration<
        Authorize,
        PaymentsAuthorizeData,
        PaymentsResponseData,
    >>::get_error_response(Flitt::new(), answer(502, b"Bad Gateway"), None)
    .unwrap();
    assert_eq!(outage.attempt_status, None);
    // A refusal body on a non-200 answer keeps Flitt's code.
    let coded = <Flitt as ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData>>::get_error_response(
        Flitt::new(),
        answer(
            500,
            br#"{"response":{"error_code":1002,"error_message":"Application error","request_id":"r1","response_status":"failure"}}"#,
        ),
        None,
    )
    .unwrap();
    assert_eq!(coded.code, "1002");
    assert_eq!(coded.message, "Application error");
    assert_eq!(coded.attempt_status, None);
}

#[test]
fn capabilities() {
    let methods = Flitt::new().get_supported_payment_methods().unwrap();
    let details = methods
        .get(&enums::PaymentMethod::BankRedirect)
        .and_then(|types| types.get(&enums::PaymentMethodType::LocalBankRedirect))
        .unwrap();
    assert_eq!(details.refunds, enums::FeatureStatus::Supported);
    assert!(details
        .supported_capture_methods
        .contains(&enums::CaptureMethod::Manual));
    // Flitt cannot cancel an unpaid order, so the router must not pretend to.
    for payment_method_type in [Some(enums::PaymentMethodType::LocalBankRedirect), None] {
        assert!(!Flitt::new().is_pre_authorize_cancel_supported(payment_method_type));
    }
    assert_eq!(Flitt::new().id(), "flitt");
    assert!(matches!(
        Flitt::new().get_currency_unit(),
        api::CurrencyUnit::Minor
    ));
}

#[test]
fn the_order_id_is_the_attempt_reference_when_authorize_left_none() {
    assert_eq!(Flitt::order_id(Some("o1".to_string()), "pay_1_1"), "o1");
    assert_eq!(Flitt::order_id(Some(String::new()), "pay_1_1"), "pay_1_1");
    assert_eq!(Flitt::order_id(None, "pay_1_1"), "pay_1_1");
}
