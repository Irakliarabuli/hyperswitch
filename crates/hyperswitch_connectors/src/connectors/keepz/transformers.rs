//! Request/response models for the Keepz eCommerce integrator API.
//!
//! Keepz exposes a hosted checkout page: the connector creates an order,
//! redirects the customer to `urlForQR`, and learns the outcome either from
//! the plain-JSON callback or by polling the order status. Amounts are
//! exchanged in major units (`12.50` GEL) and every payload travels inside
//! the hybrid-encrypted envelope implemented in [`super::crypto`].

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
        let auth = KeepzAuthType::try_from(&router_data.connector_auth_type)?;
        let return_url = router_data.request.get_router_return_url()?;
        Ok(Self {
            amount: item.amount,
            currency: router_data.request.currency,
            receiver_id: auth.receiver_id,
            receiver_type: RECEIVER_TYPE_BRANCH,
            integrator_id: auth.integrator_id,
            integrator_order_id: integrator_order_id(&router_data.connector_request_reference_id),
            success_redirect_uri: return_url.clone(),
            fail_redirect_uri: return_url,
            callback_uri: router_data.request.get_webhook_url()?,
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
/// `POST /order/refund/v2`, and also the shape of the plain callback.
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

/// Plain-JSON body Keepz POSTs to `callbackUri` once the payment settles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeepzCallbackBody {
    pub integrator_order_id: String,
    pub status: KeepzOrderStatus,
    #[serde(default)]
    pub amount: Option<f64>,
    #[serde(default)]
    pub transaction_id: Option<serde_json::Value>,
    #[serde(default)]
    pub initial_currency: Option<String>,
}

impl From<KeepzOrderStatus> for api_models::webhooks::IncomingWebhookEvent {
    fn from(status: KeepzOrderStatus) -> Self {
        match status {
            KeepzOrderStatus::Success => Self::PaymentIntentSuccess,
            KeepzOrderStatus::Failed | KeepzOrderStatus::Expired => Self::PaymentIntentFailure,
            KeepzOrderStatus::Canceled => Self::PaymentIntentCancelled,
            KeepzOrderStatus::Processing => Self::PaymentIntentProcessing,
            KeepzOrderStatus::RefundRequested
            | KeepzOrderStatus::PartiallyRefunded
            | KeepzOrderStatus::RefundedByOperator
            | KeepzOrderStatus::RefundedByIntegrator
            | KeepzOrderStatus::RefundedByKeepz
            | KeepzOrderStatus::RefundedFailed
            | KeepzOrderStatus::Initial
            | KeepzOrderStatus::Unknown => Self::EventNotSupported,
        }
    }
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
    fn callback_body_parses_and_maps_to_events() {
        use api_models::webhooks::IncomingWebhookEvent as E;
        let body = serde_json::json!({
            "amount": 12.5,
            "receiverId": "0b1f6e58-1c5f-4a7e-9d1e-3f0d7c9b2a11",
            "receiverType": "BRANCH",
            "integratorId": "6d9b0c1e-2f3a-4b5c-8d7e-9f0a1b2c3d4e",
            "integratorOrderId": "a4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "status": "SUCCESS",
            "initialCurrency": "GEL",
            "transactionId": 123456
        });
        let parsed: KeepzCallbackBody = serde_json::from_value(body).unwrap();
        assert_eq!(
            parsed.integrator_order_id,
            "a4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
        );
        assert_eq!(parsed.amount, Some(12.5));
        assert_eq!(E::from(parsed.status), E::PaymentIntentSuccess);
        assert_eq!(E::from(KeepzOrderStatus::Failed), E::PaymentIntentFailure);
        assert_eq!(
            E::from(KeepzOrderStatus::RefundRequested),
            E::EventNotSupported
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
        let request = KeepzCreateOrderRequest {
            amount,
            currency: enums::Currency::GEL,
            receiver_id: Secret::new("r".to_string()),
            receiver_type: RECEIVER_TYPE_BRANCH,
            integrator_id: Secret::new("i".to_string()),
            integrator_order_id: integrator_order_id("pay_1"),
            success_redirect_uri: "https://m/ok".to_string(),
            fail_redirect_uri: "https://m/ok".to_string(),
            callback_uri: "https://hs/webhooks/m/keepz".to_string(),
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["receiverType"], "BRANCH");
        assert_eq!(value["currency"], "GEL");
        assert_eq!(value["amount"], 10.0);
        assert!(value["callbackUri"].is_string());
    }
}
