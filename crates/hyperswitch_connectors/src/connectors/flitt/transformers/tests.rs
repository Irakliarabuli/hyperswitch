//! Unit tests of the Flitt models and state mapping. Answers in `test_data`
//! are Flitt answers of the public test merchant (merchant 1549901, payment
//! key `test`) captured on 2026-10-20; the payer IP inside `additional_info`
//! was replaced by a documentation address and the protocol 2.0 envelopes
//! re-signed with the test key.

use common_enums::enums::{AttemptStatus as A, RefundStatus as R};
use hyperswitch_masking::Secret;

use super::*;

const STATUS_CREATED: &str = include_str!("../test_data/status_created_v2.json");
const STATUS_APPROVED: &str = include_str!("../test_data/status_approved_v2.json");
const STATUS_HOLD: &str = include_str!("../test_data/status_hold_v2.json");
const STATUS_CAPTURED: &str = include_str!("../test_data/status_captured_v2.json");
const STATUS_DECLINED_ATTEMPT: &str = include_str!("../test_data/status_declined_attempt_v2.json");
const STATUS_PARTIALLY_REVERSED: &str =
    include_str!("../test_data/status_partially_reversed_v2.json");
const STATUS_REVERSED: &str = include_str!("../test_data/status_reversed_v2.json");
const STATUS_HOLD_RELEASED: &str = include_str!("../test_data/status_hold_released_v2.json");
const REVERSE_APPROVED: &str = include_str!("../test_data/reverse_approved_v2.json");
const CAPTURE_ANSWER: &str = include_str!("../test_data/capture_v2.json");
const CHECKOUT_URL: &str = include_str!("../test_data/checkout_url_v2.json");
const STATUS_NOT_FOUND: &str = include_str!("../test_data/status_not_found.json");
const CHECKOUT_DUPLICATE: &str = include_str!("../test_data/checkout_url_duplicate.json");
const REVERSE_EXCEEDS: &str = include_str!("../test_data/reverse_exceeds.json");

fn test_key() -> Secret<String> {
    Secret::new("test".to_string())
}

fn payload(answer: &str) -> serde_json::Value {
    protocol::read_answer(answer.as_bytes(), &test_key())
        .expect("readable")
        .expect("not a refusal")
}

fn order(answer: &str) -> FlittOrder {
    serde_json::from_value(payload(answer)).expect("an order")
}

fn refusal(answer: &str) -> FlittFailure {
    protocol::read_answer(answer.as_bytes(), &test_key())
        .expect("readable")
        .expect_err("a refusal")
}

fn body_key(api_key: &str, key1: &str) -> ConnectorAuthType {
    ConnectorAuthType::BodyKey {
        api_key: Secret::new(api_key.to_string()),
        key1: Secret::new(key1.to_string()),
    }
}

#[test]
fn credentials_are_the_payment_key_and_a_numeric_merchant_id() {
    let auth = FlittAuthType::try_from(&body_key(" test ", " 1549901 ")).unwrap();
    assert_eq!(auth.merchant_id, 1_549_901);
    assert_eq!(auth.payment_key.peek(), "test");
    for (api_key, key1) in [
        ("test", "abc"),
        ("test", ""),
        ("test", "0"),
        ("", "1549901"),
        (" ", "1549901"),
    ] {
        assert!(
            FlittAuthType::try_from(&body_key(api_key, key1)).is_err(),
            "{api_key:?} {key1:?}"
        );
    }
    assert!(FlittAuthType::try_from(&ConnectorAuthType::HeaderKey {
        api_key: Secret::new("test".to_string())
    })
    .is_err());
}

#[test]
fn the_bank_comes_from_payment_metadata() {
    use serde_json::json;
    assert_eq!(bank_from_metadata(None).unwrap(), None);
    for metadata in [
        json!({}),
        json!({ "flitt_bank": null }),
        json!("text"),
        json!({ "keepz_bank": "TBC" }),
    ] {
        assert_eq!(
            bank_from_metadata(Some(&metadata)).unwrap(),
            None,
            "{metadata}"
        );
    }
    for (code, bank) in [
        ("tbc", FlittBank::Tbc),
        ("bog", FlittBank::Bog),
        ("credo", FlittBank::Credo),
        ("liberty", FlittBank::Liberty),
        ("x", FlittBank::X),
    ] {
        let metadata = json!({ "flitt_bank": code, "other": 1 });
        assert_eq!(bank_from_metadata(Some(&metadata)).unwrap(), Some(bank));
        assert_eq!(bank.to_string(), code);
        assert_eq!(serde_json::to_value(bank).unwrap(), code);
    }
}

#[test]
fn an_unknown_bank_refuses_the_payment_before_flitt_is_called() {
    use serde_json::json;
    for value in [
        json!("TBC"),
        json!("Bank of Georgia"),
        json!(""),
        json!(" tbc"),
        json!("lb"),
        json!(1),
        json!(["tbc"]),
    ] {
        let metadata = json!({ "flitt_bank": value });
        assert!(bank_from_metadata(Some(&metadata)).is_err(), "{metadata}");
    }
}

#[test]
fn the_order_lifetime_defaults_to_the_payment_page_window() {
    use serde_json::json;
    assert_eq!(lifetime_from_metadata(None).unwrap(), 900);
    assert_eq!(lifetime_from_metadata(Some(&json!({}))).unwrap(), 900);
    assert_eq!(
        lifetime_from_metadata(Some(&json!({ "flitt_lifetime": null }))).unwrap(),
        900
    );
    assert_eq!(
        lifetime_from_metadata(Some(&json!({ "flitt_lifetime": 60 }))).unwrap(),
        60
    );
    assert_eq!(
        lifetime_from_metadata(Some(&json!({ "flitt_lifetime": 86400 }))).unwrap(),
        86400
    );
    for value in [
        json!(59),
        json!(86401),
        json!(0),
        json!(-5),
        json!(1.5),
        json!("900"),
        json!(true),
    ] {
        assert!(
            lifetime_from_metadata(Some(&json!({ "flitt_lifetime": value }))).is_err(),
            "{value}"
        );
    }
}

#[test]
fn the_checkout_language_follows_the_locale() {
    assert_eq!(checkout_language(Some("ka-GE")).as_deref(), Some("ka"));
    assert_eq!(checkout_language(Some("en_US")).as_deref(), Some("en"));
    assert_eq!(checkout_language(Some("RU")).as_deref(), Some("ru"));
    assert_eq!(checkout_language(Some("xx-YY")), None);
    assert_eq!(checkout_language(Some("")), None);
    assert_eq!(checkout_language(None), None);
}

fn order_request(bank: Option<FlittBank>, preauth: bool) -> FlittOrderRequest {
    FlittOrderRequest {
        merchant_id: 1_549_901,
        order_id: "pay_abc_1".to_string(),
        order_desc: "Table 12".to_string(),
        amount: MinorUnit::new(1050),
        currency: enums::Currency::GEL,
        response_url: "https://router.example/payments/pay_abc/m/redirect/response/flitt"
            .to_string(),
        server_callback_url: "https://router.example/webhooks/m/mca_1".to_string(),
        lifetime: 900,
        payment_systems: if bank.is_some() {
            PAYMENT_SYSTEMS_OPEN_BANKING
        } else {
            PAYMENT_SYSTEMS_CARD
        },
        payment_method: bank,
        preauth: preauth.then_some("Y"),
        lang: Some("ka".to_string()),
        sender_email: None,
    }
}

#[test]
fn a_card_order_asks_for_the_card_page_only() {
    let value = serde_json::to_value(order_request(None, false)).unwrap();
    assert_eq!(value["payment_systems"], "card");
    assert_eq!(value["amount"], 1050);
    assert_eq!(value["currency"], "GEL");
    assert_eq!(value["merchant_id"], 1_549_901);
    assert_eq!(value["lifetime"], 900);
    assert_eq!(value["lang"], "ka");
    for absent in ["payment_method", "preauth", "sender_email", "delayed"] {
        assert!(value.get(absent).is_none(), "{absent}");
    }
    let held = serde_json::to_value(order_request(None, true)).unwrap();
    assert_eq!(held["preauth"], "Y");
}

#[test]
fn a_bank_order_asks_for_that_bank_through_open_banking() {
    let value = serde_json::to_value(order_request(Some(FlittBank::Tbc), false)).unwrap();
    assert_eq!(value["payment_systems"], "opb");
    assert_eq!(value["payment_method"], "tbc");
}

#[test]
fn the_card_page_is_reached_through_the_router_redirect() {
    let checkout: FlittCheckout = serde_json::from_value(payload(CHECKOUT_URL)).unwrap();
    assert!(checkout.checkout_url.starts_with("https://pay.flitt.com/"));
    assert!(checkout.payment_id.is_some());
    let response = checkout_response(&checkout, None, "pay_abc_1", 1_700_000_900_000).unwrap();
    let PaymentsResponseData::TransactionResponse {
        resource_id,
        redirection_data,
        connector_metadata,
        connector_response_reference_id,
        ..
    } = response
    else {
        panic!("a transaction response");
    };
    assert_eq!(
        resource_id.get_connector_transaction_id().ok().as_deref(),
        Some("pay_abc_1")
    );
    assert_eq!(connector_metadata, None);
    assert_eq!(connector_response_reference_id, checkout.payment_id);
    match *redirection_data {
        Some(RedirectForm::Form {
            endpoint,
            method,
            form_fields,
        }) => {
            // The token travels as a field: a GET form replaces the query.
            let url = url::Url::parse(&checkout.checkout_url).unwrap();
            assert_eq!(method, Method::Get);
            assert!(!endpoint.contains('?'));
            assert_eq!(
                form_fields.get("token").map(String::as_str),
                url.query_pairs()
                    .find(|(name, _)| name == "token")
                    .map(|(_, value)| value)
                    .as_deref()
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_bank_link_is_handed_over_for_a_tap_and_a_qr_code() {
    let link = "https://api.tbcbank.ge/psd2/openbanking/oauth/authorize?client_id=x&state=y";
    let checkout = FlittCheckout {
        checkout_url: link.to_string(),
        payment_id: Some("1024217553".to_string()),
    };
    let response = checkout_response(
        &checkout,
        Some(FlittBank::Tbc),
        "pay_abc_1",
        1_700_000_900_000,
    )
    .unwrap();
    let PaymentsResponseData::TransactionResponse {
        redirection_data,
        connector_metadata,
        ..
    } = response
    else {
        panic!("a transaction response");
    };
    // No router redirect page: the bank link must not be opened by a redirect.
    assert!(redirection_data.is_none());
    let metadata = connector_metadata.expect("the bank link");
    // The router reads it back as QR code information for next_action.
    let info: QrCodeInformation = serde_json::from_value(metadata.clone()).unwrap();
    match info {
        QrCodeInformation::QrCodeUrl {
            image_data_url,
            qr_code_url,
            display_to_timestamp,
            raw_qr_data,
            ..
        } => {
            assert_eq!(qr_code_url.unwrap().as_str(), link);
            assert_eq!(raw_qr_data.as_deref(), Some(link));
            assert_eq!(display_to_timestamp, Some(1_700_000_900_000));
            assert!(image_data_url
                .as_str()
                .starts_with("data:image/png;base64,"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_checkout_url_that_is_not_https_is_refused() {
    for checkout_url in [
        "http://pay.flitt.com/x?token=1",
        "javascript:alert(1)",
        "not a url",
    ] {
        let checkout = FlittCheckout {
            checkout_url: checkout_url.to_string(),
            payment_id: None,
        };
        assert!(
            checkout_response(&checkout, None, "pay_1", 0).is_err(),
            "{checkout_url}"
        );
        assert!(
            checkout_response(&checkout, Some(FlittBank::Bog), "pay_1", 0).is_err(),
            "{checkout_url}"
        );
    }
}

#[test]
fn real_order_states_map_to_attempt_statuses() {
    let waiting = A::AuthenticationPending;
    assert_eq!(
        attempt_status(&order(STATUS_CREATED), waiting),
        A::AuthenticationPending
    );
    assert_eq!(attempt_status(&order(STATUS_APPROVED), waiting), A::Charged);
    assert_eq!(attempt_status(&order(STATUS_HOLD), waiting), A::Authorized);
    assert_eq!(
        attempt_status(&order(STATUS_CAPTURED), A::Authorized),
        A::Charged
    );
    assert_eq!(
        attempt_status(&order(STATUS_PARTIALLY_REVERSED), A::Charged),
        A::Charged
    );
    assert_eq!(
        attempt_status(&order(STATUS_REVERSED), A::Charged),
        A::Charged
    );
    assert_eq!(
        attempt_status(&order(STATUS_HOLD_RELEASED), A::Authorized),
        A::Voided
    );
    // delayed=Y: a declined attempt leaves the order payable on the same page.
    let declined_attempt = order(STATUS_DECLINED_ATTEMPT);
    assert_eq!(declined_attempt.order_status, FlittOrderStatus::Processing);
    assert_eq!(declined_attempt.response_code.as_deref(), Some("1097"));
    assert_eq!(
        attempt_status(&declined_attempt, waiting),
        A::AuthenticationPending
    );
}

#[test]
fn processing_without_a_decline_is_in_progress_and_final_states_fail() {
    let mut processing = order(STATUS_CREATED);
    processing.order_status = FlittOrderStatus::Processing;
    assert_eq!(
        attempt_status(&processing, A::AuthenticationPending),
        A::Pending
    );
    for status in [FlittOrderStatus::Declined, FlittOrderStatus::Expired] {
        let mut ended = order(STATUS_DECLINED_ATTEMPT);
        ended.order_status = status;
        assert_eq!(
            attempt_status(&ended, A::AuthenticationPending),
            A::Failure,
            "{status}"
        );
        let error = order_error(&ended, 200);
        assert_eq!(error.code, "1097");
        assert_eq!(error.message, "Decline, refer to card issuer");
        assert_eq!(
            error.connector_transaction_id.as_deref(),
            Some(ended.order_id.as_str())
        );
    }
    let mut expired = order(STATUS_CREATED);
    expired.order_status = FlittOrderStatus::Expired;
    assert_eq!(order_error(&expired, 200).code, "expired");
}

#[test]
fn a_late_callback_never_takes_a_settled_payment_back() {
    let created = order(STATUS_CREATED);
    let declined_attempt = order(STATUS_DECLINED_ATTEMPT);
    for settled in [A::Charged, A::Authorized, A::Voided, A::PartialCharged] {
        assert_eq!(attempt_status(&created, settled), settled, "{settled:?}");
        assert_eq!(
            attempt_status(&declined_attempt, settled),
            settled,
            "{settled:?}"
        );
    }
    // A payment Flitt really approved after a local failure is still charged.
    assert_eq!(
        attempt_status(&order(STATUS_APPROVED), A::Failure),
        A::Charged
    );
    // An unknown state keeps the current one.
    let mut unknown = order(STATUS_CREATED);
    unknown.order_status = serde_json::from_str("\"something_new\"").unwrap();
    assert_eq!(unknown.order_status, FlittOrderStatus::Unknown);
    assert_eq!(attempt_status(&unknown, A::Pending), A::Pending);
}

#[test]
fn callbacks_select_the_payments_flow() {
    use api_models::webhooks::WebhookFlow;
    let cases = [
        (
            STATUS_CREATED,
            IncomingWebhookEvent::PaymentIntentProcessing,
        ),
        (
            STATUS_DECLINED_ATTEMPT,
            IncomingWebhookEvent::PaymentIntentProcessing,
        ),
        (STATUS_APPROVED, IncomingWebhookEvent::PaymentIntentSuccess),
        (
            STATUS_HOLD,
            IncomingWebhookEvent::PaymentIntentAuthorizationSuccess,
        ),
        (STATUS_REVERSED, IncomingWebhookEvent::PaymentIntentSuccess),
        (
            STATUS_HOLD_RELEASED,
            IncomingWebhookEvent::PaymentIntentCancelled,
        ),
    ];
    for (answer, event) in cases {
        assert_eq!(webhook_event(&order(answer)), event);
        assert!(matches!(WebhookFlow::from(event), WebhookFlow::Payment));
    }
    let mut declined = order(STATUS_DECLINED_ATTEMPT);
    declined.order_status = FlittOrderStatus::Declined;
    assert_eq!(
        webhook_event(&declined),
        IncomingWebhookEvent::PaymentIntentFailure
    );
}

#[test]
fn refusals_keep_flitt_code_message_and_request_id() {
    let not_found = refusal(STATUS_NOT_FOUND);
    let error = failure_error(&not_found, 200, Some(A::Pending));
    assert_eq!(error.code, "1018");
    assert_eq!(error.message, "Order not found");
    assert!(error.reason.unwrap().contains("Flitt request"));
    assert_eq!(error.attempt_status, Some(A::Pending));
    assert_eq!(
        refusal(CHECKOUT_DUPLICATE).error_code.as_deref(),
        Some("1013")
    );
    assert_eq!(refusal(REVERSE_EXCEEDS).error_code.as_deref(), Some("1127"));
    let empty = failure_error(&FlittFailure::default(), 502, None);
    assert_eq!(empty.code, consts::NO_ERROR_CODE);
    assert_eq!(empty.message, consts::NO_ERROR_MESSAGE);
}

#[test]
fn a_refused_create_order_leaves_the_payment_payable() {
    assert_eq!(REFUSED_ORDER_ATTEMPT_STATUS, A::PaymentMethodAwaited);
    assert_eq!(
        enums::IntentStatus::from(REFUSED_ORDER_ATTEMPT_STATUS),
        enums::IntentStatus::RequiresPaymentMethod
    );
}

#[test]
fn a_reversal_answer_maps_to_refund_and_void_statuses() {
    let answer: FlittReverseAnswer = serde_json::from_value(payload(REVERSE_APPROVED)).unwrap();
    assert_eq!(answer.refund_status(), R::Success);
    assert_eq!(answer.void_status(), A::Voided);
    assert_eq!(answer.reverse_id.as_deref(), Some("ref_fixture_1"));
    // Flitt's own id of the reversal is kept as the connector refund id.
    assert_eq!(
        answer.connector_refund_id("ref_fixture_1"),
        answer.transaction_id.clone().unwrap()
    );
    for (status, refund, void) in [
        (FlittOrderStatus::Declined, R::Failure, A::VoidFailed),
        (FlittOrderStatus::Processing, R::Pending, A::VoidInitiated),
        (FlittOrderStatus::Created, R::Pending, A::VoidInitiated),
        (FlittOrderStatus::Unknown, R::Pending, A::VoidInitiated),
    ] {
        let other = FlittReverseAnswer {
            reverse_status: status,
            transaction_id: None,
            ..answer.clone()
        };
        assert_eq!(other.refund_status(), refund, "{status}");
        assert_eq!(other.void_status(), void, "{status}");
        assert_eq!(other.connector_refund_id("ref_x"), "ref_fixture_1");
    }
}

#[test]
fn a_capture_answer_maps_to_attempt_statuses() {
    let answer: FlittCaptureAnswer = serde_json::from_value(payload(CAPTURE_ANSWER)).unwrap();
    assert_eq!(answer.attempt_status(), A::Charged);
    let declined = FlittCaptureAnswer {
        capture_status: Some("declined".to_string()),
        response_code: Some("1000".to_string()),
        response_description: Some("General decline".to_string()),
        ..answer.clone()
    };
    assert_eq!(declined.attempt_status(), A::CaptureFailed);
    assert_eq!(declined.error(200).code, "1000");
    let pending = FlittCaptureAnswer {
        capture_status: Some("hold".to_string()),
        ..answer
    };
    assert_eq!(pending.attempt_status(), A::CaptureInitiated);
}

#[test]
fn reverse_ids_are_stable_and_fit_flitt() {
    assert_eq!(reverse_id("ref_01HZYX"), "ref_01HZYX");
    let long = "r".repeat(64);
    assert_eq!(reverse_id(&long), reverse_id(&long));
    assert!(reverse_id(&long).len() <= 50);
    assert_ne!(reverse_id(&long), reverse_id(&"s".repeat(64)));
    assert!(reverse_id("ref_ქართული").is_ascii());
    assert_eq!(void_reverse_id("pay_abc_1"), "void_pay_abc_1");
    assert!(void_reverse_id(&"p".repeat(60)).len() <= 50);
    assert_eq!(reverse_comment(Some("  ")), None);
    assert_eq!(
        reverse_comment(Some(" guest asked ")).as_deref(),
        Some("guest asked")
    );
}

#[test]
fn values_flitt_sends_as_numbers_strings_or_nothing_all_read() {
    let order: FlittOrder = serde_json::from_value(serde_json::json!({
        "order_id": "o1", "order_status": "approved", "merchant_id": 1549901,
        "response_code": 1097, "payment_id": "805230052", "amount": "", "rrn": null
    }))
    .unwrap();
    assert_eq!(order.merchant_id.as_deref(), Some("1549901"));
    assert_eq!(order.response_code.as_deref(), Some("1097"));
    assert_eq!(order.payment_id.as_deref(), Some("805230052"));
    assert_eq!(order.amount, None);
    assert_eq!(order.rrn, None);
    assert_eq!(order.capture_state(), FlittCaptureState::NotHeld);
}

/// A protocol 2.0 callback for `order` of `merchant_id`, signed with `key`.
fn signed_callback(order: &serde_json::Value, key: &str) -> Vec<u8> {
    let request = protocol::encode_request(&Secret::new(key.to_string()), order).unwrap();
    serde_json::to_vec(&serde_json::json!({
        "version": "2.0", "data": request.request.data, "signature": request.request.signature
    }))
    .unwrap()
}

#[test]
fn only_a_signed_envelope_of_this_merchant_is_a_verified_callback() {
    let auth = FlittAuthType::try_from(&body_key("test", "1549901")).unwrap();
    let approved = payload(STATUS_APPROVED);
    assert!(is_verified_callback(
        &signed_callback(&approved, "test"),
        &auth
    ));
    // Signed with another key.
    assert!(!is_verified_callback(
        &signed_callback(&approved, "other"),
        &auth
    ));
    // Signed with this key, about another merchant.
    let mut other_merchant = approved.clone();
    other_merchant["merchant_id"] = serde_json::json!(1_000_001);
    assert!(!is_verified_callback(
        &signed_callback(&other_merchant, "test"),
        &auth
    ));
    // A flat callback with a valid value signature is still not verified.
    let mut flat = approved.as_object().unwrap().clone();
    let signature = protocol::sign_flat(&test_key(), &flat);
    flat.insert(
        "signature".to_string(),
        serde_json::Value::String(signature),
    );
    let flat = serde_json::to_vec(&flat).unwrap();
    assert!(!is_verified_callback(&flat, &auth));
    // Its order can still be named, so the router can ask Flitt about it.
    assert_eq!(
        callback_order(&flat).unwrap().order_id,
        order(STATUS_APPROVED).order_id
    );
    let noise: [&[u8]; 4] = [
        b"not json",
        b"{}",
        b"[]",
        br#"{"response":{"error_code":1014,"response_status":"failure"}}"#,
    ];
    for noise in noise {
        assert!(!is_verified_callback(noise, &auth));
        assert!(callback_order(noise).is_err());
    }
}
