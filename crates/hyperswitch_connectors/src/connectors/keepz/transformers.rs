//! Request/response models for the Keepz eCommerce integrator API.
//!
//! Keepz exposes a hosted checkout page: the connector creates an order,
//! redirects the customer to `urlForQR`, and learns the outcome by asking for
//! the order status; the Keepz callback only says which order to ask about
//! (see "Callback"). Amounts are exchanged in major units (`12.50` GEL) and
//! every payload travels inside the hybrid-encrypted envelope implemented in
//! [`super::crypto`].

use common_enums::enums;
use common_utils::{request::Method, types::FloatMajorUnit};
use hyperswitch_domain_models::{
    payment_method_data::{BankRedirectData, PaymentMethodData},
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::{consts, errors};
use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{self, PaymentsAuthorizeRequestData},
};

const RECEIVER_TYPE_BRANCH: &str = "BRANCH";
const REFUND_INITIATOR: &str = "INTEGRATOR";

pub struct KeepzRouterData<T> {
    pub amount: FloatMajorUnit,
    pub router_data: T,
}

impl<T> From<(FloatMajorUnit, T)> for KeepzRouterData<T> {
    fn from((amount, router_data): (FloatMajorUnit, T)) -> Self {
        Self {
            amount,
            router_data,
        }
    }
}

/// Merchant connector account credentials.
///
/// Mapped from `ConnectorAuthType::MultiAuthKey`:
/// - `api_key`    -> Keepz integrator id (UUID)
/// - `key1`       -> Keepz RSA public key (PEM or base64 DER)
/// - `api_secret` -> integrator RSA private key (PEM or base64 PKCS#8 DER)
/// - `key2`       -> receiver (branch) id that collects the funds
pub struct KeepzAuthType {
    pub(super) integrator_id: Secret<String>,
    pub(super) keepz_public_key: Secret<String>,
    pub(super) integrator_private_key: Secret<String>,
    pub(super) receiver_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for KeepzAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                integrator_id: api_key.to_owned(),
                keepz_public_key: key1.to_owned(),
                integrator_private_key: api_secret.to_owned(),
                receiver_id: key2.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

/// Keepz requires `integratorOrderId` to be a UUID v4, while Hyperswitch
/// attempt ids are not. Derive a stable, UUID-shaped identifier from the
/// attempt reference so the same attempt always maps to the same Keepz order.
pub fn integrator_order_id(reference: &str) -> String {
    let digest = Sha256::digest(reference.as_bytes());
    let mut bytes = [0u8; 16];
    for (dst, src) in bytes.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    uuid::Uuid::from_bytes(bytes).hyphenated().to_string()
}

// ---------------------------------------------------------------------------
// Direct bank link (open banking)
// ---------------------------------------------------------------------------

// Keepz can skip its own page and send the payer straight to one bank's open
// banking flow: the create-order field `openBankingLinkProvider` (an
// integrator permission at Keepz). `urlForQR` is then the bank's own
// authorization URL (for TBC, `api.tbcbank.ge/psd2/openbanking/oauth/authorize`,
// seen on the development gateway on 2026-10-15) and the order is
// `PROCESSING` from the start. `BankRedirectData::LocalBankRedirect {}` has no
// fields and `common_enums::BankNames` has no Georgian banks, so the choice
// travels in the payment's metadata under `keepz_bank`.

/// Payment metadata key naming the bank for a direct open-banking link.
pub const BANK_METADATA_KEY: &str = "keepz_bank";

/// Keepz' `OpenBankingProvider` values (its validation error lists exactly
/// these): Bank of Georgia, TBC, Credo, Liberty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeepzOpenBankingProvider {
    Bog,
    Tbc,
    Credo,
    Lb,
}

/// The bank named by `metadata.keepz_bank`: absent or null is no bank (the
/// Keepz page, as before); one of the Keepz values, spelled exactly, is that
/// bank; anything else refuses the payment before Keepz is called.
pub fn open_banking_provider(
    metadata: Option<&serde_json::Value>,
) -> Result<Option<KeepzOpenBankingProvider>, error_stack::Report<errors::ConnectorError>> {
    match metadata.and_then(|metadata| metadata.get(BANK_METADATA_KEY)) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone()).map(Some).map_err(|_| {
            error_stack::report!(errors::ConnectorError::InvalidDataFormat {
                field_name: "metadata.keepz_bank".into(),
            })
        }),
    }
}

/// The attempt status for a create-order Keepz refused with a 4xx answer.
///
/// A refused create-order creates no order at Keepz (checked on the
/// development gateway: the refused id is unknown to the status call
/// afterwards), so nothing is pending and nothing can be charged. The
/// payment is left waiting for a payment method rather than failed, so the
/// same payment, and the same attempt with the same derived order id, can be
/// confirmed again: without the bank when Keepz refused the bank, or by card.
/// Anything else (5xx, timeouts) keeps the router's default handling, because
/// there the order may exist.
pub fn refused_order_attempt_status(http_code: u16) -> Option<enums::AttemptStatus> {
    (400..=499)
        .contains(&http_code)
        .then_some(enums::AttemptStatus::PaymentMethodAwaited)
}

// ---------------------------------------------------------------------------
// Create order (Authorize)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzCreateOrderRequest {
    pub amount: FloatMajorUnit,
    pub currency: enums::Currency,
    pub receiver_id: Secret<String>,
    pub receiver_type: &'static str,
    pub integrator_id: Secret<String>,
    pub integrator_order_id: String,
    pub success_redirect_uri: String,
    pub fail_redirect_uri: String,
    pub callback_uri: String,
    /// Sent only for a direct bank link (see `open_banking_provider`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_banking_link_provider: Option<KeepzOpenBankingProvider>,
}

impl TryFrom<&KeepzRouterData<&PaymentsAuthorizeRouterData>> for KeepzCreateOrderRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &KeepzRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        match &router_data.request.payment_method_data {
            PaymentMethodData::BankRedirect(BankRedirectData::LocalBankRedirect {}) => {}
            _ => Err(errors::ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Keepz"),
            ))?,
        }
        let open_banking_link_provider =
            open_banking_provider(router_data.request.metadata.as_ref())?;
        let auth = KeepzAuthType::try_from(&router_data.connector_auth_type)?;
        let return_url = router_data.request.get_router_return_url()?;
        let order_id = integrator_order_id(&router_data.connector_request_reference_id);
        let callback_uri = callback_uri(&router_data.request.get_webhook_url()?, &order_id)?;
        Ok(Self {
            amount: item.amount,
            currency: router_data.request.currency,
            receiver_id: auth.receiver_id,
            receiver_type: RECEIVER_TYPE_BRANCH,
            integrator_id: auth.integrator_id,
            integrator_order_id: order_id,
            success_redirect_uri: return_url.clone(),
            fail_redirect_uri: return_url,
            callback_uri,
            open_banking_link_provider,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzCreateOrderResponse {
    pub integrator_order_id: String,
    #[serde(rename = "urlForQR")]
    pub url_for_qr: String,
}

impl<F, T> TryFrom<ResponseRouterData<F, KeepzCreateOrderResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, KeepzCreateOrderResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let redirection_data = RedirectForm::Form {
            endpoint: item.response.url_for_qr,
            method: Method::Get,
            form_fields: Default::default(),
        };
        Ok(Self {
            status: enums::AttemptStatus::AuthenticationPending,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.integrator_order_id),
                redirection_data: Box::new(Some(redirection_data)),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: Some(
                    item.data.connector_request_reference_id.clone(),
                ),
                incremental_authorization_allowed: None,
                authentication_data: None,
                charges: None,
                payment_account_reference: None,
            }),
            ..item.data
        })
    }
}

// ---------------------------------------------------------------------------
// Shared status model (PSync, Void, Refund, RSync, callback)
// ---------------------------------------------------------------------------

/// Encrypted payload shared by status, cancel and refund calls.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzOrderReference {
    pub integrator_id: Secret<String>,
    pub integrator_order_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum KeepzOrderStatus {
    Initial,
    Processing,
    Success,
    Failed,
    #[serde(alias = "CANCELLED")]
    Canceled,
    Expired,
    RefundRequested,
    PartiallyRefunded,
    RefundedByOperator,
    RefundedByIntegrator,
    RefundedByKeepz,
    RefundedFailed,
    #[serde(other)]
    Unknown,
}

impl KeepzOrderStatus {
    /// Payment-level view of an order status. `Unknown` keeps the current
    /// Hyperswitch status untouched.
    pub fn attempt_status(self, current: enums::AttemptStatus) -> enums::AttemptStatus {
        match self {
            Self::Initial => enums::AttemptStatus::AuthenticationPending,
            Self::Processing => enums::AttemptStatus::Pending,
            Self::Success
            | Self::RefundRequested
            | Self::PartiallyRefunded
            | Self::RefundedByOperator
            | Self::RefundedByIntegrator
            | Self::RefundedByKeepz
            | Self::RefundedFailed => enums::AttemptStatus::Charged,
            Self::Failed | Self::Expired => enums::AttemptStatus::Failure,
            Self::Canceled => enums::AttemptStatus::Voided,
            Self::Unknown => current,
        }
    }

    /// Refund-level view of an order status. Keepz has no refund ids, so the
    /// order status is the only signal for refund progress.
    pub fn refund_status(self) -> enums::RefundStatus {
        match self {
            Self::PartiallyRefunded
            | Self::RefundedByOperator
            | Self::RefundedByIntegrator
            | Self::RefundedByKeepz => enums::RefundStatus::Success,
            Self::RefundedFailed | Self::Failed | Self::Canceled | Self::Expired => {
                enums::RefundStatus::Failure
            }
            Self::RefundRequested
            | Self::Success
            | Self::Initial
            | Self::Processing
            | Self::Unknown => enums::RefundStatus::Pending,
        }
    }
}

/// Decrypted body of `GET /order/status`, `DELETE /order/cancel` and
/// `POST /order/refund/v2`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzOrderStatusResponse {
    pub integrator_order_id: String,
    pub status: KeepzOrderStatus,
    #[serde(default)]
    pub transaction_id: Option<serde_json::Value>,
    #[serde(default)]
    pub amount: Option<f64>,
    #[serde(default)]
    pub original_amount: Option<f64>,
}

impl<F, T> TryFrom<ResponseRouterData<F, KeepzOrderStatusResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, KeepzOrderStatusResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = item.response.status.attempt_status(item.data.status);
        let response = if utils::is_payment_failure(status) {
            Err(payment_failure(&item.response, item.http_code))
        } else {
            Ok(transaction_response(
                &item.response,
                &item.data.connector_request_reference_id,
            ))
        };
        Ok(Self {
            status,
            response,
            ..item.data
        })
    }
}

fn transaction_response(
    response: &KeepzOrderStatusResponse,
    reference_id: &str,
) -> PaymentsResponseData {
    PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(response.integrator_order_id.clone()),
        redirection_data: Box::new(None),
        mandate_reference: Box::new(None),
        connector_metadata: None,
        network_txn_id: None,
        network_txn_link_id: None,
        connector_response_reference_id: Some(reference_id.to_owned()),
        incremental_authorization_allowed: None,
        authentication_data: None,
        charges: None,
        payment_account_reference: None,
    }
}

fn payment_failure(response: &KeepzOrderStatusResponse, http_code: u16) -> ErrorResponse {
    let status = response.status.to_string();
    ErrorResponse {
        status_code: http_code,
        code: status.clone(),
        message: status.clone(),
        reason: Some(status),
        attempt_status: None,
        connector_transaction_id: Some(response.integrator_order_id.clone()),
        connector_response_reference_id: None,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
        connector_metadata: None,
    }
}

// ---------------------------------------------------------------------------
// Refunds
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzRefundRequest {
    pub integrator_id: Secret<String>,
    pub integrator_order_id: String,
    pub amount: FloatMajorUnit,
    pub refund_initiator: &'static str,
}

impl<F> TryFrom<&KeepzRouterData<&RefundsRouterData<F>>> for KeepzRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &KeepzRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        let auth = KeepzAuthType::try_from(&item.router_data.connector_auth_type)?;
        Ok(Self {
            integrator_id: auth.integrator_id,
            integrator_order_id: item.router_data.request.connector_transaction_id.clone(),
            amount: item.amount,
            refund_initiator: REFUND_INITIATOR,
        })
    }
}

impl TryFrom<RefundsResponseRouterData<Execute, KeepzOrderStatusResponse>>
    for RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, KeepzOrderStatusResponse>,
    ) -> Result<Self, Self::Error> {
        // Keepz processes refunds asynchronously and returns REFUND_REQUESTED;
        // the final state is picked up by RSync against the order status.
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.integrator_order_id,
                refund_status: enums::RefundStatus::Pending,
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, KeepzOrderStatusResponse>>
    for RefundsRouterData<RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, KeepzOrderStatusResponse>,
    ) -> Result<Self, Self::Error> {
        let refund_status = item.response.status.refund_status();
        let response = if utils::is_refund_failure(refund_status) {
            Err(payment_failure(&item.response, item.http_code))
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: item.response.integrator_order_id,
                refund_status,
            })
        };
        Ok(Self {
            response,
            ..item.data
        })
    }
}

// ---------------------------------------------------------------------------
// Callback (incoming webhook)
// ---------------------------------------------------------------------------

// Keepz POSTs to the order's `callbackUri` once the payment settles. The body
// is not the plain JSON its documentation shows: it is the hybrid envelope
// (`{ encryptedData, aes, encryptedKeys }`) sealed to the integrator's key,
// and it carries no signature. The connector therefore never reads it. It
// neither decrypts it (that would put the integrator private key on a public,
// unauthenticated endpoint and turn the endpoint into a decryption oracle)
// nor trusts anything in it. The callback is only a trigger: the order to ask
// Keepz about is named in the callback URL itself, which we choose per order,
// and the router then runs a real, authenticated order-status call.

/// Query parameter on `callbackUri` that names the order.
pub const CALLBACK_REFERENCE_PARAM: &str = "ref";

/// The event every callback is treated as, whatever its body says. It only
/// selects the router's payments flow; with an unverified source that flow
/// syncs the payment with Keepz and takes the status from that answer.
pub const CALLBACK_EVENT: api_models::webhooks::IncomingWebhookEvent =
    api_models::webhooks::IncomingWebhookEvent::PaymentIntentProcessing;

/// The per-order callback URL: the router's webhook URL plus the Keepz order
/// id (`?ref=<integratorOrderId>`).
pub fn callback_uri(
    webhook_url: &str,
    integrator_order_id: &str,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    let mut url = url::Url::parse(webhook_url).map_err(|_| {
        error_stack::report!(errors::ConnectorError::RequestEncodingFailed)
            .attach_printable("The webhook URL for the Keepz callback is not a valid URL")
    })?;
    url.query_pairs_mut()
        .append_pair(CALLBACK_REFERENCE_PARAM, integrator_order_id);
    Ok(url.to_string())
}

/// Reads the order id back from a callback's query string. Only exactly one
/// `ref` parameter in the canonical form this connector writes (a lowercase,
/// hyphenated UUID) is a reference; anything else is none.
pub fn callback_reference(query: &str) -> Option<String> {
    let mut references = url::form_urlencoded::parse(query.as_bytes())
        .filter_map(|(name, value)| (name == CALLBACK_REFERENCE_PARAM).then(|| value.into_owned()));
    let reference = references.next()?;
    if references.next().is_some() {
        return None;
    }
    let parsed = uuid::Uuid::try_parse(&reference).ok()?;
    (parsed.hyphenated().to_string() == reference).then_some(reference)
}

/// What the router logs as the callback's content: the order id from the
/// URL. Nothing from the body.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzCallbackTrigger {
    pub integrator_order_id: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Keepz error bodies are plain JSON, never encrypted.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzErrorResponse {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub status_code: Option<i64>,
    #[serde(default)]
    pub exception_group: Option<i64>,
}

impl KeepzErrorResponse {
    pub fn code(&self) -> String {
        self.status_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| consts::NO_ERROR_CODE.to_owned())
    }

    pub fn message(&self) -> String {
        self.message
            .clone()
            .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrator_order_id_is_a_stable_uuid_v4() {
        let first = integrator_order_id("pay_abc_1");
        let second = integrator_order_id("pay_abc_1");
        let other = integrator_order_id("pay_abc_2");
        assert_eq!(first, second);
        assert_ne!(first, other);
        let parsed = uuid::Uuid::parse_str(&first).expect("valid uuid");
        assert_eq!(parsed.get_version_num(), 4);
        assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);
    }

    #[test]
    fn status_mapping_for_payments() {
        use enums::AttemptStatus as A;
        let current = A::Pending;
        assert_eq!(
            KeepzOrderStatus::Initial.attempt_status(current),
            A::AuthenticationPending
        );
        assert_eq!(
            KeepzOrderStatus::Processing.attempt_status(current),
            A::Pending
        );
        assert_eq!(
            KeepzOrderStatus::Success.attempt_status(current),
            A::Charged
        );
        assert_eq!(
            KeepzOrderStatus::PartiallyRefunded.attempt_status(current),
            A::Charged
        );
        assert_eq!(KeepzOrderStatus::Failed.attempt_status(current), A::Failure);
        assert_eq!(
            KeepzOrderStatus::Expired.attempt_status(current),
            A::Failure
        );
        assert_eq!(
            KeepzOrderStatus::Canceled.attempt_status(current),
            A::Voided
        );
        assert_eq!(KeepzOrderStatus::Unknown.attempt_status(current), current);
    }

    #[test]
    fn status_mapping_for_refunds() {
        use enums::RefundStatus as R;
        assert_eq!(
            KeepzOrderStatus::RefundRequested.refund_status(),
            R::Pending
        );
        assert_eq!(
            KeepzOrderStatus::RefundedByIntegrator.refund_status(),
            R::Success
        );
        assert_eq!(
            KeepzOrderStatus::PartiallyRefunded.refund_status(),
            R::Success
        );
        assert_eq!(KeepzOrderStatus::RefundedFailed.refund_status(), R::Failure);
        assert_eq!(KeepzOrderStatus::Success.refund_status(), R::Pending);
    }

    #[test]
    fn status_deserializes_both_cancel_spellings_and_unknown_values() {
        let canceled: KeepzOrderStatus = serde_json::from_str("\"CANCELED\"").unwrap();
        let cancelled: KeepzOrderStatus = serde_json::from_str("\"CANCELLED\"").unwrap();
        let unknown: KeepzOrderStatus = serde_json::from_str("\"SOMETHING_NEW\"").unwrap();
        assert_eq!(canceled, KeepzOrderStatus::Canceled);
        assert_eq!(cancelled, KeepzOrderStatus::Canceled);
        assert_eq!(unknown, KeepzOrderStatus::Unknown);
    }

    #[test]
    fn callback_uri_names_the_order_in_its_query() {
        let order_id = integrator_order_id("pay_abc_1");
        assert_eq!(
            callback_uri("https://hs.example.test/webhooks/merchant_1/mca_1", &order_id).unwrap(),
            format!("https://hs.example.test/webhooks/merchant_1/mca_1?ref={order_id}")
        );
        // A query that is already there is kept.
        assert_eq!(
            callback_uri("https://hs.example.test/webhooks/m/mca_1?x=1", &order_id).unwrap(),
            format!("https://hs.example.test/webhooks/m/mca_1?x=1&ref={order_id}")
        );
        assert!(callback_uri("not a url", &order_id).is_err());
    }

    #[test]
    fn callback_reference_round_trips_through_the_callback_uri() {
        let order_id = integrator_order_id("pay_abc_1");
        let uri = callback_uri("https://hs.example.test/webhooks/m/mca_1", &order_id).unwrap();
        let query = url::Url::parse(&uri).unwrap().query().unwrap().to_string();
        assert_eq!(callback_reference(&query), Some(order_id));
    }

    #[test]
    fn callback_reference_accepts_only_one_canonical_uuid() {
        let id = "a4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
        assert_eq!(callback_reference(&format!("ref={id}")), Some(id.to_string()));
        assert_eq!(
            callback_reference(&format!("utm=1&ref={id}&other=x")),
            Some(id.to_string())
        );
        for query in [
            String::new(),
            "ref=".to_string(),
            "ref".to_string(),
            format!("reference={id}"),
            format!("REF={id}"),
            // More than one reference is no reference.
            format!("ref={id}&ref={id}"),
            format!("ref={id}&ref=b4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"),
            // Other spellings of the same UUID.
            format!("ref={}", id.to_uppercase()),
            format!("ref={}", id.replace('-', "")),
            format!("ref=%7B{id}%7D"),
            format!("ref=urn:uuid:{id}"),
            // Not a UUID, or a UUID with something attached.
            "ref=pay_abc_1".to_string(),
            "ref=../../payments".to_string(),
            format!("ref={id}%20"),
            format!("ref={id}x"),
            format!("ref={id}%00"),
            "ref=a4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5".to_string(),
            "ref=g4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".to_string(),
        ] {
            assert_eq!(callback_reference(&query), None, "{query}");
        }
    }

    #[test]
    fn every_callback_is_the_same_trigger_event() {
        use api_models::webhooks::{IncomingWebhookEvent as E, WebhookFlow};
        assert_eq!(CALLBACK_EVENT, E::PaymentIntentProcessing);
        // The payments flow: with an unverified source the router syncs.
        assert!(matches!(WebhookFlow::from(CALLBACK_EVENT), WebhookFlow::Payment));
        let trigger = KeepzCallbackTrigger {
            integrator_order_id: "a4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&trigger).unwrap(),
            serde_json::json!({ "integratorOrderId": "a4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d" })
        );
    }

    #[test]
    fn create_order_response_parses_url_for_qr() {
        let body = serde_json::json!({
            "integratorOrderId": "a4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "urlForQR": "https://pay.dev.keepz.me/o/abc"
        });
        let parsed: KeepzCreateOrderResponse = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.url_for_qr, "https://pay.dev.keepz.me/o/abc");
    }

    #[test]
    fn error_response_is_lenient() {
        let full: KeepzErrorResponse = serde_json::from_str(
            r#"{"message":"Order not found","statusCode":6006,"exceptionGroup":3}"#,
        )
        .unwrap();
        assert_eq!(full.code(), "6006");
        assert_eq!(full.message(), "Order not found");
        let empty: KeepzErrorResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.code(), consts::NO_ERROR_CODE);
    }

    #[test]
    fn create_order_request_serializes_camel_case() {
        let amount = utils::convert_amount(
            &common_utils::types::FloatMajorUnitForConnector,
            common_utils::types::MinorUnit::new(1000),
            enums::Currency::GEL,
        )
        .unwrap();
        let request = order_request(amount, None);
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["receiverType"], "BRANCH");
        assert_eq!(value["currency"], "GEL");
        assert_eq!(value["amount"], 10.0);
        assert!(value["callbackUri"].is_string());
    }

    fn order_request(
        amount: FloatMajorUnit,
        bank: Option<KeepzOpenBankingProvider>,
    ) -> KeepzCreateOrderRequest {
        KeepzCreateOrderRequest {
            amount,
            currency: enums::Currency::GEL,
            receiver_id: Secret::new("r".to_string()),
            receiver_type: RECEIVER_TYPE_BRANCH,
            integrator_id: Secret::new("i".to_string()),
            integrator_order_id: integrator_order_id("pay_1"),
            success_redirect_uri: "https://m/ok".to_string(),
            fail_redirect_uri: "https://m/ok".to_string(),
            callback_uri: "https://hs/webhooks/m/keepz".to_string(),
            open_banking_link_provider: bank,
        }
    }

    fn one_lari() -> FloatMajorUnit {
        utils::convert_amount(
            &common_utils::types::FloatMajorUnitForConnector,
            common_utils::types::MinorUnit::new(100),
            enums::Currency::GEL,
        )
        .unwrap()
    }

    #[test]
    fn create_order_sends_the_bank_only_when_one_was_chosen() {
        let with_bank =
            serde_json::to_value(order_request(one_lari(), Some(KeepzOpenBankingProvider::Tbc)))
                .unwrap();
        assert_eq!(with_bank["openBankingLinkProvider"], "TBC");
        // Never the card variant: that is a different Keepz permission.
        assert!(with_bank.get("directLinkProvider").is_none());

        let without_bank = serde_json::to_value(order_request(one_lari(), None)).unwrap();
        let fields: Vec<&String> = without_bank.as_object().unwrap().keys().collect();
        assert!(!fields.iter().any(|field| field.ends_with("LinkProvider")), "{fields:?}");
        assert_eq!(fields.len(), 9, "{fields:?}");
    }

    #[test]
    fn every_keepz_bank_value_serializes_as_keepz_spells_it() {
        for (bank, spelled) in [
            (KeepzOpenBankingProvider::Bog, "BOG"),
            (KeepzOpenBankingProvider::Tbc, "TBC"),
            (KeepzOpenBankingProvider::Credo, "CREDO"),
            (KeepzOpenBankingProvider::Lb, "LB"),
        ] {
            assert_eq!(serde_json::to_value(bank).unwrap(), spelled);
        }
    }

    #[test]
    fn the_bank_comes_from_payment_metadata() {
        use serde_json::json;
        assert_eq!(open_banking_provider(None).unwrap(), None);
        for metadata in [
            json!({}),
            json!({ "payment_attempt_id": "payatt_1" }),
            json!({ "keepz_bank": null }),
            json!("not an object"),
        ] {
            assert_eq!(open_banking_provider(Some(&metadata)).unwrap(), None, "{metadata}");
        }
        for (value, bank) in [
            ("BOG", KeepzOpenBankingProvider::Bog),
            ("TBC", KeepzOpenBankingProvider::Tbc),
            ("CREDO", KeepzOpenBankingProvider::Credo),
            ("LB", KeepzOpenBankingProvider::Lb),
        ] {
            let metadata = json!({ "payment_attempt_id": "payatt_1", "keepz_bank": value });
            assert_eq!(open_banking_provider(Some(&metadata)).unwrap(), Some(bank));
        }
    }

    #[test]
    fn an_unknown_bank_refuses_the_payment_before_keepz_is_called() {
        use serde_json::json;
        for value in [
            json!("tbc"),
            json!("Bank of Georgia"),
            json!("XYZ"),
            json!(""),
            json!(" TBC"),
            json!(1),
            json!(true),
            json!(["TBC"]),
            json!({ "bank": "TBC" }),
        ] {
            let metadata = json!({ "keepz_bank": value });
            assert!(open_banking_provider(Some(&metadata)).is_err(), "{metadata}");
        }
    }

    #[test]
    fn a_refused_order_leaves_the_payment_payable_and_nothing_else_does() {
        for http_code in [400, 401, 403, 404, 409, 422, 429, 499] {
            assert_eq!(
                refused_order_attempt_status(http_code),
                Some(enums::AttemptStatus::PaymentMethodAwaited),
                "{http_code}"
            );
        }
        for http_code in [200, 201, 302, 399, 500, 502, 503, 504, 511, 599] {
            assert_eq!(refused_order_attempt_status(http_code), None, "{http_code}");
        }
        // The router turns that attempt status into an unsubmitted payment,
        // which the payments API lets the merchant confirm again.
        assert_eq!(
            enums::IntentStatus::from(enums::AttemptStatus::PaymentMethodAwaited),
            enums::IntentStatus::RequiresPaymentMethod
        );
        assert!(!enums::AttemptStatus::PaymentMethodAwaited.is_payment_terminal_failure());
    }
}
