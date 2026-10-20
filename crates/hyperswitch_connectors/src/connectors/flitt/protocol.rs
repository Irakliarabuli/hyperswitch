//! Flitt's wire protocol: the signed request envelope, and reading and
//! verifying Flitt's answers and server callbacks.
//!
//! Every request is sent as protocol 2.0:
//! `{"request": {"version": "2.0", "data": <base64 of {"order": params}>,
//! "signature": sha1("<payment key>|<data>")}}`. Flitt answers an order created
//! this way in the same envelope (status, capture and reverse answers included),
//! signed the same way, so the signature covers the exact JSON text and with it
//! every field name (seen on the public test merchant on 2026-10-20).
//!
//! Protocol 1.0.1 (flat parameters, SHA-1 over the non-empty values ordered by
//! parameter name, joined with `|`) is still understood when reading, because
//! Flitt answers refusals flat and unsigned and a flat order answers flat. Its
//! signature covers values only, not names: a payer, who receives the same
//! signed values on the browser return, can move a value under another name.
//! A flat callback is therefore never treated as verified; it only triggers a
//! status request (see `super::Flitt::verify_webhook_source`).

use common_utils::{consts::BASE64_ENGINE, errors::CustomResult};
use error_stack::{report, ResultExt};
use hyperswitch_interfaces::errors::ConnectorError;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

/// The protocol version this connector sends.
pub const PROTOCOL_VERSION: &str = "2.0";

/// Parameters that never take part in a protocol 1.0.1 signature.
/// `response_signature_string` is Flitt's test-mode hint of what it signed.
const UNSIGNED_FLAT_FIELDS: [&str; 2] = ["signature", "response_signature_string"];

/// The body of every Flitt API request.
#[derive(Debug, Clone, Serialize)]
pub struct FlittRequest {
    pub request: FlittEnvelope,
}

/// A protocol 2.0 envelope, as sent and as received.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlittEnvelope {
    pub version: String,
    pub data: String,
    pub signature: String,
}

/// Lowercase hex SHA-1 of `text`.
fn sha1_hex(text: &str) -> String {
    hex::encode(Sha1::digest(text.as_bytes()))
}

/// The protocol 2.0 signature of a base64 `data` string.
pub fn sign_data(payment_key: &Secret<String>, data: &str) -> String {
    sha1_hex(&format!("{}|{data}", payment_key.peek()))
}

/// The protocol 1.0.1 signature of flat parameters: the key, then every
/// non-empty value ordered by parameter name, joined with `|`. Numbers and
/// booleans are signed as their JSON text; `0` and `"0"` are values.
pub fn sign_flat(
    payment_key: &Secret<String>,
    params: &serde_json::Map<String, serde_json::Value>,
) -> String {
    let mut names: Vec<&String> = params
        .iter()
        .filter(|(name, value)| {
            !UNSIGNED_FLAT_FIELDS.contains(&name.as_str()) && flat_value(value).is_some()
        })
        .map(|(name, _)| name)
        .collect();
    names.sort();
    let mut text = payment_key.peek().clone();
    for name in names {
        if let Some(value) = params.get(name).and_then(flat_value) {
            text.push('|');
            text.push_str(&value);
        }
    }
    sha1_hex(&text)
}

/// The text a flat value is signed as; `None` for an absent value.
fn flat_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) if text.is_empty() => None,
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        // Flitt never sends nested values flat; they sign as nothing.
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => None,
    }
}

/// Compares two hex signatures in constant time (case-insensitive).
pub fn signatures_match(expected: &str, received: &str) -> bool {
    let expected = expected.to_ascii_lowercase();
    let received = received.trim().to_ascii_lowercase();
    if expected.len() != received.len() {
        return false;
    }
    expected
        .bytes()
        .zip(received.bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

/// Builds the signed protocol 2.0 request for `params`.
pub fn encode_request<T: Serialize>(
    payment_key: &Secret<String>,
    params: &T,
) -> CustomResult<FlittRequest, ConnectorError> {
    let json = serde_json::to_vec(&serde_json::json!({ "order": params }))
        .change_context(ConnectorError::RequestEncodingFailed)?;
    let data = base64::Engine::encode(&BASE64_ENGINE, json);
    let signature = sign_data(payment_key, &data);
    Ok(FlittRequest {
        request: FlittEnvelope {
            version: PROTOCOL_VERSION.to_string(),
            data,
            signature,
        },
    })
}

/// A request Flitt refused (`response_status: failure`, always with HTTP 200).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlittFailure {
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub request_id: Option<String>,
}

/// What a Flitt answer or callback says, once unwrapped.
#[derive(Debug, Clone, PartialEq)]
pub enum FlittMessage {
    /// A protocol 2.0 envelope: the decoded object (the content of its
    /// `order` key) and whether its signature matched the payment key.
    Enveloped {
        payload: serde_json::Value,
        signature_valid: bool,
    },
    /// Flat (protocol 1.0.1) parameters; `signature_valid` is `None` when the
    /// body carries no signature.
    Flat {
        payload: serde_json::Value,
        signature_valid: Option<bool>,
    },
    /// Flitt refused the request.
    Failure(FlittFailure),
}

/// The object inside `{"response": ...}`, or the body itself (callbacks come
/// without the wrapper).
pub fn unwrap_root(body: &serde_json::Value) -> &serde_json::Value {
    match body.get("response") {
        Some(inner) if inner.is_object() => inner,
        _ => body,
    }
}

/// Reads an answer or callback. A signature is checked against
/// `payment_key` when one is given and the body is signed.
pub fn read(
    body: &[u8],
    payment_key: Option<&Secret<String>>,
) -> CustomResult<FlittMessage, ConnectorError> {
    let parsed: serde_json::Value = serde_json::from_slice(body)
        .change_context(ConnectorError::ResponseDeserializationFailed)?;
    let root = unwrap_root(&parsed);
    if !root.is_object() {
        return Err(report!(ConnectorError::ResponseDeserializationFailed)
            .attach_printable("A Flitt answer is not a JSON object"));
    }
    if let Some(failure) = failure_of(root) {
        return Ok(FlittMessage::Failure(failure));
    }
    if let (Some(data), Some(signature)) = (
        root.get("data").and_then(serde_json::Value::as_str),
        root.get("signature").and_then(serde_json::Value::as_str),
    ) {
        let payload = decode_data(data)?;
        if let Some(failure) = failure_of(&payload) {
            return Ok(FlittMessage::Failure(failure));
        }
        let signature_valid = payment_key
            .map(|key| signatures_match(&sign_data(key, data), signature))
            .unwrap_or(false);
        return Ok(FlittMessage::Enveloped {
            payload,
            signature_valid,
        });
    }
    let signature_valid = match (
        root.get("signature").and_then(serde_json::Value::as_str),
        root.as_object(),
        payment_key,
    ) {
        (None, _, _) => None,
        (Some(signature), Some(params), Some(key)) => {
            Some(signatures_match(&sign_flat(key, params), signature))
        }
        (Some(_), _, _) => Some(false),
    };
    Ok(FlittMessage::Flat {
        payload: root.clone(),
        signature_valid,
    })
}

/// Reads an API answer: a refusal is returned as such, and anything signed
/// must carry a valid signature (fail closed).
pub fn read_answer(
    body: &[u8],
    payment_key: &Secret<String>,
) -> CustomResult<Result<serde_json::Value, FlittFailure>, ConnectorError> {
    match read(body, Some(payment_key))? {
        FlittMessage::Failure(failure) => Ok(Err(failure)),
        FlittMessage::Enveloped {
            payload,
            signature_valid: true,
        }
        | FlittMessage::Flat {
            payload,
            signature_valid: None | Some(true),
        } => Ok(Ok(payload)),
        FlittMessage::Enveloped {
            signature_valid: false,
            ..
        }
        | FlittMessage::Flat {
            signature_valid: Some(false),
            ..
        } => Err(report!(ConnectorError::ResponseDeserializationFailed)
            .attach_printable("The signature of a Flitt answer does not match the payment key")),
    }
}

/// Decodes a protocol 2.0 `data` string to the object under its `order` key
/// (or the whole document when it has no such key).
pub fn decode_data(data: &str) -> CustomResult<serde_json::Value, ConnectorError> {
    let bytes = base64::Engine::decode(&BASE64_ENGINE, data.trim())
        .change_context(ConnectorError::ResponseDeserializationFailed)
        .attach_printable("A Flitt envelope's data is not base64")?;
    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .change_context(ConnectorError::ResponseDeserializationFailed)
        .attach_printable("A Flitt envelope's data is not JSON")?;
    let payload = match document.get("order") {
        Some(order) if order.is_object() => order.clone(),
        _ => document,
    };
    if payload.is_object() {
        Ok(payload)
    } else {
        Err(report!(ConnectorError::ResponseDeserializationFailed)
            .attach_printable("A Flitt envelope's data is not an object"))
    }
}

/// A refusal: `response_status: failure`, or a non-empty `error_code`
/// (some Flitt endpoints say "success" next to an error code).
fn failure_of(root: &serde_json::Value) -> Option<FlittFailure> {
    let failed = root
        .get("response_status")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|status| status.eq_ignore_ascii_case("failure"));
    let error_code = root.get("error_code").and_then(flat_value);
    if !failed && error_code.is_none() {
        return None;
    }
    Some(FlittFailure {
        error_code,
        error_message: root.get("error_message").and_then(flat_value),
        request_id: root.get("request_id").and_then(flat_value),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public test merchant's payment key (docs.flitt.com, Testing).
    fn test_key() -> Secret<String> {
        Secret::new("test".to_string())
    }

    /// A real flat (1.0.1) status answer of the public test merchant,
    /// captured on 2026-10-20 (from a temporary build host), with Flitt's own
    /// signature.
    const FLAT_STATUS: &str = r#"{"response":{"rrn":"","masked_card":"","sender_cell_phone":"","sender_account":"","currency":"GEL","fee":"","reversal_amount":"0","settlement_amount":"0","actual_amount":"","response_description":"","sender_email":"","order_status":"created","response_status":"success","order_time":"20.10.2026 15:16:27","actual_currency":"","order_id":"drp_vector_1792498587","tran_type":"purchase","eci":"","settlement_date":"","payment_system":"","approval_code":"","merchant_id":1549901,"settlement_currency":"","payment_id":1024231285,"card_bin":"","response_code":"","card_type":"","amount":"150","signature":"75bb9df3b43c167542bdfba6695e45c2525c6746","product_id":"","merchant_data":"","rectoken":"","rectoken_lifetime":"","verification_status":"","parent_order_id":"","additional_info":"{\"capture_status\": null, \"capture_amount\": null, \"reservation_data\": \"{}\", \"transaction_id\": null, \"bank_response_code\": null, \"bank_response_description\": null, \"client_fee\": null, \"settlement_fee\": 0.0, \"bank_name\": null, \"bank_country\": null, \"card_type\": null, \"card_product\": null, \"card_category\": null, \"timeend\": null, \"ipaddress_v4\": \"18.199.160.202\", \"payment_method\": null}","fee_oplata":"0"}}"#;

    #[test]
    fn the_request_is_a_signed_protocol_2_envelope() {
        #[derive(Serialize)]
        struct Params {
            order_id: &'static str,
            amount: i64,
        }
        let request = encode_request(
            &test_key(),
            &Params {
                order_id: "o1",
                amount: 150,
            },
        )
        .unwrap();
        assert_eq!(request.request.version, "2.0");
        assert_eq!(
            request.request.signature,
            sha1_hex(&format!("test|{}", request.request.data))
        );
        assert_eq!(
            decode_data(&request.request.data).unwrap(),
            serde_json::json!({ "order_id": "o1", "amount": 150 })
        );
        let body = serde_json::to_value(&request).unwrap();
        assert!(body["request"]["data"].is_string());
    }

    #[test]
    fn the_documented_flat_signature_string_is_reproduced() {
        // docs.flitt.com "Signature": test|1000|GEL|1549901|Test payment|TestOrder2|http://myshop/callback/
        let params = serde_json::json!({
            "server_callback_url": "http://myshop/callback/",
            "order_id": "TestOrder2",
            "currency": "GEL",
            "merchant_id": 1549901,
            "order_desc": "Test payment",
            "amount": 1000,
            "empty": "",
            "nothing": null
        });
        assert_eq!(
            sign_flat(&test_key(), params.as_object().unwrap()),
            sha1_hex("test|1000|GEL|1549901|Test payment|TestOrder2|http://myshop/callback/")
        );
    }

    #[test]
    fn a_real_flat_answer_verifies_and_a_changed_one_does_not() {
        match read(FLAT_STATUS.as_bytes(), Some(&test_key())).unwrap() {
            FlittMessage::Flat {
                payload,
                signature_valid,
            } => {
                assert_eq!(signature_valid, Some(true));
                assert_eq!(payload["order_status"], "created");
            }
            other => panic!("{other:?}"),
        }
        let tampered = FLAT_STATUS.replace(
            "\"order_status\":\"created\"",
            "\"order_status\":\"approved\"",
        );
        assert!(read_answer(tampered.as_bytes(), &test_key()).is_err());
        let wrong_key = Secret::new("other".to_string());
        assert!(read_answer(FLAT_STATUS.as_bytes(), &wrong_key).is_err());
    }

    #[test]
    fn an_envelope_verifies_only_with_its_key_and_data() {
        let request = encode_request(
            &test_key(),
            &serde_json::json!({ "order_status": "approved" }),
        )
        .unwrap();
        let answer = serde_json::json!({ "response": {
            "version": "2.0", "data": request.request.data, "signature": request.request.signature,
            "response_status": "success" } });
        let body = serde_json::to_vec(&answer).unwrap();
        assert_eq!(
            read_answer(&body, &test_key()).unwrap().unwrap()["order_status"],
            "approved"
        );
        assert!(read_answer(&body, &Secret::new("x".to_string())).is_err());
        // The same envelope without the wrapper (as a callback) reads the same.
        let bare = serde_json::to_vec(&answer["response"]).unwrap();
        assert!(matches!(
            read(&bare, Some(&test_key())).unwrap(),
            FlittMessage::Enveloped {
                signature_valid: true,
                ..
            }
        ));
        // A signature made for other data does not verify this data.
        let other = encode_request(
            &test_key(),
            &serde_json::json!({ "order_status": "declined" }),
        )
        .unwrap();
        let mut forged = answer.clone();
        forged["response"]["signature"] = serde_json::Value::String(other.request.signature);
        let forged = serde_json::to_vec(&forged).unwrap();
        assert!(matches!(
            read(&forged, Some(&test_key())).unwrap(),
            FlittMessage::Enveloped {
                signature_valid: false,
                ..
            }
        ));
        assert!(read_answer(&forged, &test_key()).is_err());
        // Without a key nothing is verified.
        assert!(matches!(
            read(&body, None).unwrap(),
            FlittMessage::Enveloped {
                signature_valid: false,
                ..
            }
        ));
    }

    #[test]
    fn a_refusal_is_read_as_a_failure() {
        for body in [
            r#"{"response":{"error_code":1018,"error_message":"Order not found","request_id":"j3Ed7O4Jhu7Yv","response_status":"failure"}}"#,
            r#"{"response":{"error_code":"1013","error_message":"Duplicate order","response_status":"success"}}"#,
        ] {
            match read_answer(body.as_bytes(), &test_key()).unwrap() {
                Err(failure) => {
                    assert!(failure.error_code.is_some());
                    assert!(failure.error_message.is_some());
                }
                Ok(other) => panic!("{other}"),
            }
        }
    }

    #[test]
    fn signatures_compare_in_full() {
        assert!(signatures_match("abc123", "ABC123"));
        assert!(signatures_match("abc123", " abc123 "));
        assert!(!signatures_match("abc123", "abc12"));
        assert!(!signatures_match("abc123", "abc124"));
        assert!(!signatures_match("abc123", ""));
    }

    #[test]
    fn what_is_not_json_or_not_an_object_is_refused() {
        assert!(read(b"<html>", Some(&test_key())).is_err());
        assert!(read(b"[1,2]", Some(&test_key())).is_err());
        assert!(read(
            br#"{"response":{"version":"2.0","data":"%%%","signature":"x"}}"#,
            Some(&test_key())
        )
        .is_err());
    }
}
