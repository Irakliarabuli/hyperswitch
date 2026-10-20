//! Request and answer models of the Flitt payment API (pay.flitt.com), and how
//! Flitt's order states map onto Hyperswitch.
//!
//! The payer never gives card data to us: a payment is a Flitt order paid on
//! Flitt's own checkout page (cards with 3-D Secure, Apple Pay, Google Pay) or
//! in the payer's bank (open banking). Amounts are integers in minor units.

use api_models::{payments::QrCodeInformation, webhooks::IncomingWebhookEvent};
use common_enums::enums;
use common_utils::{request::Method, types::MinorUnit};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    payment_method_data::{BankRedirectData, PaymentMethodData},
    router_data::{ConnectorAuthType, ErrorResponse},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RedirectForm},
    types::PaymentsAuthorizeRouterData,
};
use hyperswitch_interfaces::{consts, errors::ConnectorError};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use super::protocol::{self, FlittFailure, FlittMessage};
use crate::utils::{self, PaymentsAuthorizeRequestData};

pub struct FlittRouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> From<(MinorUnit, T)> for FlittRouterData<T> {
    fn from((amount, router_data): (MinorUnit, T)) -> Self {
        Self {
            amount,
            router_data,
        }
    }
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Merchant connector account credentials (`ConnectorAuthType::BodyKey`):
/// - `api_key` -> the payment secret key (portal.flitt.com -> Merchant
///   settings -> Technical); it signs every request, answer and callback
/// - `key1`    -> the Flitt merchant ID (a number)
#[derive(Debug, Clone)]
pub struct FlittAuthType {
    pub(super) merchant_id: u64,
    pub(super) payment_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FlittAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        let ConnectorAuthType::BodyKey { api_key, key1 } = auth_type else {
            return Err(ConnectorError::FailedToObtainAuthType.into());
        };
        let merchant_id = key1
            .peek()
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|id| *id > 0)
            .ok_or(ConnectorError::InvalidConnectorConfig {
                config: "key1 (the Flitt merchant ID, a number)",
            })?;
        let payment_key = api_key.peek().trim().to_string();
        if payment_key.is_empty() {
            return Err(ConnectorError::InvalidConnectorConfig {
                config: "api_key (the Flitt payment secret key)",
            }
            .into());
        }
        Ok(Self {
            merchant_id,
            payment_key: Secret::new(payment_key),
        })
    }
}

// ---------------------------------------------------------------------------
// Payment metadata the platform sends
// ---------------------------------------------------------------------------

/// Payment metadata key naming the payer's bank for an open-banking payment.
pub const BANK_METADATA_KEY: &str = "flitt_bank";
/// Payment metadata key overriding the order lifetime, in seconds.
pub const LIFETIME_METADATA_KEY: &str = "flitt_lifetime";
/// Order lifetime when the payment names none: the router's own payment-page
/// window (15 minutes). Flitt expires an unpaid order after it.
pub const DEFAULT_LIFETIME_SECONDS: u32 = 900;
const MIN_LIFETIME_SECONDS: u32 = 60;
const MAX_LIFETIME_SECONDS: u32 = 86_400;

/// Flitt's open-banking banks (`payment_method` with `payment_systems=opb`).
/// `x` is Flitt's demo bank, which only the test merchant knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum FlittBank {
    Tbc,
    Bog,
    Credo,
    Liberty,
    X,
}

/// The bank named by `metadata.flitt_bank`: absent or null is no bank (the
/// card checkout page); one of Flitt's codes, spelled exactly, is that bank;
/// anything else refuses the payment before Flitt is called.
pub fn bank_from_metadata(
    metadata: Option<&serde_json::Value>,
) -> Result<Option<FlittBank>, error_stack::Report<ConnectorError>> {
    match metadata.and_then(|metadata| metadata.get(BANK_METADATA_KEY)) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|_| {
                report!(ConnectorError::InvalidDataFormat {
                    field_name: "metadata.flitt_bank".into(),
                })
            }),
    }
}

/// The order lifetime: `metadata.flitt_lifetime` (whole seconds, 60 to
/// 86400) or the default.
pub fn lifetime_from_metadata(
    metadata: Option<&serde_json::Value>,
) -> Result<u32, error_stack::Report<ConnectorError>> {
    match metadata.and_then(|metadata| metadata.get(LIFETIME_METADATA_KEY)) {
        None | Some(serde_json::Value::Null) => Ok(DEFAULT_LIFETIME_SECONDS),
        Some(value) => value
            .as_u64()
            .and_then(|seconds| u32::try_from(seconds).ok())
            .filter(|seconds| (MIN_LIFETIME_SECONDS..=MAX_LIFETIME_SECONDS).contains(seconds))
            .ok_or_else(|| {
                report!(ConnectorError::InvalidDataFormat {
                    field_name: "metadata.flitt_lifetime".into(),
                })
            }),
    }
}

/// Checkout page languages Flitt supports (`lang`).
const CHECKOUT_LANGUAGES: [&str; 20] = [
    "az", "cs", "da", "de", "en", "es", "fi", "fr", "hu", "it", "ka", "ko", "lv", "nl", "pl", "ro",
    "ru", "sk", "uk", "zh",
];

/// The checkout language for a locale such as `ka-GE` or `en_US`, when Flitt
/// has it; otherwise Flitt picks one from the browser.
pub fn checkout_language(locale: Option<&str>) -> Option<String> {
    let primary = locale?
        .split(['-', '_'])
        .next()?
        .trim()
        .to_ascii_lowercase();
    CHECKOUT_LANGUAGES
        .contains(&primary.as_str())
        .then_some(primary)
}

// ---------------------------------------------------------------------------
// Create order (Authorize)
// ---------------------------------------------------------------------------

/// `payment_systems` for the checkout page: cards, which on Flitt's page also
/// carry Apple Pay and Google Pay. Excludes open banking and installments.
pub const PAYMENT_SYSTEMS_CARD: &str = "card";
/// `payment_systems` for open banking.
pub const PAYMENT_SYSTEMS_OPEN_BANKING: &str = "opb";
const ORDER_DESCRIPTION_MAX_CHARS: usize = 1024;

/// `POST /api/checkout/url`.
#[derive(Debug, Clone, Serialize)]
pub struct FlittOrderRequest {
    pub merchant_id: u64,
    pub order_id: String,
    pub order_desc: String,
    pub amount: MinorUnit,
    pub currency: enums::Currency,
    pub response_url: String,
    pub server_callback_url: String,
    pub lifetime: u32,
    pub payment_systems: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<FlittBank>,
    /// `Y`: hold the amount until a capture (cards only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preauth: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_email: Option<common_utils::pii::Email>,
}

impl TryFrom<&FlittRouterData<&PaymentsAuthorizeRouterData>> for FlittOrderRequest {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: &FlittRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        match &router_data.request.payment_method_data {
            PaymentMethodData::BankRedirect(BankRedirectData::LocalBankRedirect {}) => {}
            _ => Err(ConnectorError::NotImplemented(
                utils::get_unimplemented_payment_method_error_message("Flitt"),
            ))?,
        }
        let auth = FlittAuthType::try_from(&router_data.connector_auth_type)?;
        let metadata = router_data.request.metadata.as_ref();
        let bank = bank_from_metadata(metadata)?;
        let lifetime = lifetime_from_metadata(metadata)?;
        let preauth = if router_data.request.is_auto_capture()? {
            None
        } else if bank.is_some() {
            // Flitt holds funds for cards only; a bank payment is charged at once.
            return Err(ConnectorError::NotSupported {
                message: "Manual capture of an open banking payment".to_string(),
                connector: "Flitt",
            }
            .into());
        } else {
            Some("Y")
        };
        let order_id = router_data.connector_request_reference_id.clone();
        let order_desc = router_data
            .description
            .as_deref()
            .map(str::trim)
            .filter(|description| !description.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("Payment {order_id}"))
            .chars()
            .take(ORDER_DESCRIPTION_MAX_CHARS)
            .collect();
        let locale = router_data.request.locale.clone().or_else(|| {
            router_data
                .request
                .get_optional_language_from_browser_info()
        });
        Ok(Self {
            merchant_id: auth.merchant_id,
            order_id,
            order_desc,
            amount: item.amount,
            currency: router_data.request.currency,
            response_url: router_data.request.get_router_return_url()?,
            server_callback_url: router_data.request.get_webhook_url()?,
            lifetime,
            payment_systems: if bank.is_some() {
                PAYMENT_SYSTEMS_OPEN_BANKING
            } else {
                PAYMENT_SYSTEMS_CARD
            },
            payment_method: bank,
            preauth,
            lang: checkout_language(locale.as_deref()),
            sender_email: router_data.request.email.clone(),
        })
    }
}

/// The create-order answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlittCheckout {
    pub checkout_url: String,
    #[serde(default, deserialize_with = "flexible_string")]
    pub payment_id: Option<String>,
}

/// What an order Flitt accepted leaves for the payer.
///
/// - Cards and wallets: Flitt's checkout page, reached through the router's
///   own redirect page (`next_action.redirect_to_url`).
/// - A bank: `checkout_url` is the bank's own HTTPS deeplink (in production;
///   the test merchant answers with a Flitt page). Flitt's rules for it are
///   that it is opened exactly as given, directly from a visible tap, at top
///   level and never in a frame, with a QR code on desktop. An auto-redirect
///   page can open web banking instead of the bank app, so the link is handed
///   to the platform as `next_action.qr_code_information` (`qr_code_url` and
///   `raw_qr_data` = the link, `image_data_url` = its QR code,
///   `display_to_timestamp` = the order's expiry in unix milliseconds).
pub fn checkout_response(
    checkout: &FlittCheckout,
    bank: Option<FlittBank>,
    order_id: &str,
    expires_at_ms: i64,
) -> Result<PaymentsResponseData, error_stack::Report<ConnectorError>> {
    let url = url::Url::parse(&checkout.checkout_url)
        .change_context(ConnectorError::ResponseHandlingFailed)
        .attach_printable("Flitt's checkout_url is not a URL")?;
    if url.scheme() != "https" {
        return Err(report!(ConnectorError::ResponseHandlingFailed)
            .attach_printable("Flitt's checkout_url is not https"));
    }
    let (redirection_data, connector_metadata) = match bank {
        None => (Some(RedirectForm::from((url, Method::Get))), None),
        Some(_) => (
            None,
            Some(bank_handoff(&checkout.checkout_url, expires_at_ms)?),
        ),
    };
    Ok(PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(order_id.to_string()),
        redirection_data: Box::new(redirection_data),
        mandate_reference: Box::new(None),
        connector_metadata,
        network_txn_id: None,
        network_txn_link_id: None,
        connector_response_reference_id: checkout.payment_id.clone(),
        incremental_authorization_allowed: None,
        authentication_data: None,
        charges: None,
        payment_account_reference: None,
    })
}

/// The bank link as Hyperswitch QR code information.
pub fn bank_handoff(
    link: &str,
    expires_at_ms: i64,
) -> Result<serde_json::Value, error_stack::Report<ConnectorError>> {
    let image = utils::QrImage::new_from_data(link.to_string())
        .change_context(ConnectorError::ResponseHandlingFailed)?;
    let image_data_url =
        url::Url::parse(&image.data).change_context(ConnectorError::ResponseHandlingFailed)?;
    let qr_code_url =
        url::Url::parse(link).change_context(ConnectorError::ResponseHandlingFailed)?;
    serde_json::to_value(QrCodeInformation::QrCodeUrl {
        image_data_url,
        qr_code_url: Some(qr_code_url),
        display_to_timestamp: Some(expires_at_ms),
        expiry_type: None,
        raw_qr_data: Some(link.to_string()),
    })
    .change_context(ConnectorError::ResponseHandlingFailed)
}

/// The attempt status of a create-order Flitt refused. A refused create-order
/// creates no order, so nothing can be paid or charged: the payment is left
/// waiting for a payment method rather than failed, and can be confirmed
/// again (for example without the bank Flitt refused).
pub const REFUSED_ORDER_ATTEMPT_STATUS: enums::AttemptStatus =
    enums::AttemptStatus::PaymentMethodAwaited;

// ---------------------------------------------------------------------------
// Status, capture and reverse requests
// ---------------------------------------------------------------------------

/// `POST /api/status/order_id`.
#[derive(Debug, Clone, Serialize)]
pub struct FlittOrderReference {
    pub merchant_id: u64,
    pub order_id: String,
}

/// `POST /api/capture/order_id`.
#[derive(Debug, Clone, Serialize)]
pub struct FlittCaptureRequest {
    pub merchant_id: u64,
    pub order_id: String,
    pub amount: MinorUnit,
    pub currency: enums::Currency,
}

/// `POST /api/reverse/order_id`: a refund, or the release of a hold.
#[derive(Debug, Clone, Serialize)]
pub struct FlittReverseRequest {
    pub merchant_id: u64,
    pub order_id: String,
    pub amount: MinorUnit,
    pub currency: enums::Currency,
    /// Flitt's idempotency key: the same id and amount answer with the same
    /// reversal instead of a second one.
    pub reverse_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

const REVERSE_ID_MAX_CHARS: usize = 50;
const COMMENT_MAX_CHARS: usize = 1024;

/// Flitt's `reverse_id` for a Hyperswitch id: the id itself when it fits
/// Flitt's 50 characters, otherwise a stable hash of it, so a retry of the
/// same refund always sends the same key.
pub fn reverse_id(id: &str) -> String {
    if id.len() <= REVERSE_ID_MAX_CHARS && id.is_ascii() {
        id.to_string()
    } else {
        let digest = hex::encode(Sha256::digest(id.as_bytes()));
        format!("hs_{}", &digest[..40])
    }
}

/// The `reverse_id` that releases the hold of an order.
pub fn void_reverse_id(order_id: &str) -> String {
    reverse_id(&format!("void_{order_id}"))
}

/// A refund reason as Flitt's `comment`.
pub fn reverse_comment(reason: Option<&str>) -> Option<String> {
    reason
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(|reason| reason.chars().take(COMMENT_MAX_CHARS).collect())
}

// ---------------------------------------------------------------------------
// Order state
// ---------------------------------------------------------------------------

/// `order_status` of an order (and `reverse_status` of a reversal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum FlittOrderStatus {
    /// Created; the payer has not paid yet.
    Created,
    /// Being processed. With Flitt's default `delayed=Y` this is also the
    /// state after a declined attempt (with a `response_code`) while the payer
    /// may still try again on the same page.
    Processing,
    Approved,
    /// Declined (with `delayed=Y`: declined and the lifetime is over).
    Declined,
    /// Not paid within its lifetime.
    Expired,
    /// Fully reversed (refunded, or a hold released).
    Reversed,
    #[serde(other)]
    Unknown,
}

/// An order as Flitt's status answer and callbacks describe it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlittOrder {
    pub order_id: String,
    pub order_status: FlittOrderStatus,
    #[serde(default, deserialize_with = "flexible_string")]
    pub merchant_id: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub response_code: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub response_description: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub amount: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub actual_amount: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub reversal_amount: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub currency: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub payment_id: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub payment_system: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub tran_type: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub masked_card: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub card_type: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub rrn: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub approval_code: Option<String>,
    /// A JSON document as text (`capture_status`, `capture_amount`, ...).
    #[serde(default, deserialize_with = "flexible_string")]
    pub additional_info: Option<String>,
}

/// The part of `additional_info` this connector reads.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FlittAdditionalInfo {
    #[serde(default)]
    pub capture_status: Option<String>,
    #[serde(default)]
    pub capture_amount: Option<f64>,
}

/// `capture_status` of a held (preauth) order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlittCaptureState {
    /// Held, not captured.
    Hold,
    Captured,
    /// Not a hold (`capture_status` null): charged at once.
    NotHeld,
    Other,
}

impl FlittOrder {
    pub fn additional_info(&self) -> FlittAdditionalInfo {
        self.additional_info
            .as_deref()
            .and_then(|text| serde_json::from_str(text).ok())
            .unwrap_or_default()
    }

    pub fn capture_state(&self) -> FlittCaptureState {
        match self.additional_info().capture_status.as_deref() {
            None | Some("") => FlittCaptureState::NotHeld,
            Some("hold") => FlittCaptureState::Hold,
            Some("captured") => FlittCaptureState::Captured,
            Some(_) => FlittCaptureState::Other,
        }
    }

    /// A declined attempt Flitt reports on an order that stays payable.
    pub fn has_declined_attempt(&self) -> bool {
        self.response_code.is_some()
    }
}

/// Attempt statuses a stale answer or a late, retried callback must never
/// move back to "waiting": Flitt's order never goes from these back to
/// created or processing.
fn is_settled(status: enums::AttemptStatus) -> bool {
    matches!(
        status,
        enums::AttemptStatus::Charged
            | enums::AttemptStatus::PartialCharged
            | enums::AttemptStatus::PartialChargedAndChargeable
            | enums::AttemptStatus::Authorized
            | enums::AttemptStatus::PartiallyAuthorized
            | enums::AttemptStatus::Voided
            | enums::AttemptStatus::VoidedPostCharge
            | enums::AttemptStatus::AutoRefunded
    )
}

/// The attempt status an order snapshot means, given the current one.
pub fn attempt_status(order: &FlittOrder, current: enums::AttemptStatus) -> enums::AttemptStatus {
    let next = match order.order_status {
        FlittOrderStatus::Created => enums::AttemptStatus::AuthenticationPending,
        FlittOrderStatus::Processing if order.has_declined_attempt() => {
            enums::AttemptStatus::AuthenticationPending
        }
        FlittOrderStatus::Processing => enums::AttemptStatus::Pending,
        FlittOrderStatus::Approved => match order.capture_state() {
            FlittCaptureState::Hold => enums::AttemptStatus::Authorized,
            FlittCaptureState::Captured | FlittCaptureState::NotHeld | FlittCaptureState::Other => {
                enums::AttemptStatus::Charged
            }
        },
        FlittOrderStatus::Declined | FlittOrderStatus::Expired => enums::AttemptStatus::Failure,
        FlittOrderStatus::Reversed => match order.capture_state() {
            // A hold released before any capture.
            FlittCaptureState::Hold => enums::AttemptStatus::Voided,
            // A charged order refunded in full: the payment stays charged;
            // refunds are tracked as refunds.
            FlittCaptureState::Captured | FlittCaptureState::NotHeld | FlittCaptureState::Other => {
                enums::AttemptStatus::Charged
            }
        },
        FlittOrderStatus::Unknown => current,
    };
    let waiting = matches!(
        next,
        enums::AttemptStatus::AuthenticationPending | enums::AttemptStatus::Pending
    );
    if waiting && is_settled(current) {
        current
    } else {
        next
    }
}

/// The incoming-webhook event a callback's order state stands for. It only
/// selects the router's payments flow; the status comes from the order itself.
pub fn webhook_event(order: &FlittOrder) -> IncomingWebhookEvent {
    match order.order_status {
        FlittOrderStatus::Approved if order.capture_state() == FlittCaptureState::Hold => {
            IncomingWebhookEvent::PaymentIntentAuthorizationSuccess
        }
        FlittOrderStatus::Approved => IncomingWebhookEvent::PaymentIntentSuccess,
        FlittOrderStatus::Declined | FlittOrderStatus::Expired => {
            IncomingWebhookEvent::PaymentIntentFailure
        }
        FlittOrderStatus::Reversed if order.capture_state() == FlittCaptureState::Hold => {
            IncomingWebhookEvent::PaymentIntentCancelled
        }
        FlittOrderStatus::Reversed => IncomingWebhookEvent::PaymentIntentSuccess,
        FlittOrderStatus::Created | FlittOrderStatus::Processing | FlittOrderStatus::Unknown => {
            IncomingWebhookEvent::PaymentIntentProcessing
        }
    }
}

/// A payment response naming the Flitt order.
pub fn transaction_response(
    order_id: &str,
    connector_response_reference_id: Option<String>,
) -> PaymentsResponseData {
    PaymentsResponseData::TransactionResponse {
        resource_id: ResponseId::ConnectorTransactionId(order_id.to_string()),
        redirection_data: Box::new(None),
        mandate_reference: Box::new(None),
        connector_metadata: None,
        network_txn_id: None,
        network_txn_link_id: None,
        connector_response_reference_id,
        incremental_authorization_allowed: None,
        authentication_data: None,
        charges: None,
        payment_account_reference: None,
    }
}

/// The payment response for an order that is not a failure; the attempt's
/// connector metadata (a bank link while the payer is still in the bank) is
/// kept.
pub fn order_response(
    order: &FlittOrder,
    connector_metadata: Option<serde_json::Value>,
) -> PaymentsResponseData {
    let mut response = transaction_response(&order.order_id, order.payment_id.clone());
    if let PaymentsResponseData::TransactionResponse {
        connector_metadata: metadata,
        ..
    } = &mut response
    {
        *metadata = connector_metadata;
    }
    response
}

/// The error of a declined or expired order.
pub fn order_error(order: &FlittOrder, http_code: u16) -> ErrorResponse {
    let status = order.order_status.to_string();
    let code = order
        .response_code
        .clone()
        .unwrap_or_else(|| status.clone());
    let message = order
        .response_description
        .clone()
        .unwrap_or_else(|| format!("The Flitt order is {status}"));
    ErrorResponse {
        status_code: http_code,
        code,
        message: message.clone(),
        reason: Some(message),
        attempt_status: None,
        connector_transaction_id: Some(order.order_id.clone()),
        connector_response_reference_id: order.payment_id.clone(),
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
        connector_metadata: None,
    }
}

/// The error of a request Flitt refused (`error_code`, `error_message`,
/// `request_id`; always HTTP 200).
pub fn failure_error(
    failure: &FlittFailure,
    http_code: u16,
    attempt_status: Option<enums::AttemptStatus>,
) -> ErrorResponse {
    let message = failure
        .error_message
        .clone()
        .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string());
    ErrorResponse {
        status_code: http_code,
        code: failure
            .error_code
            .clone()
            .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
        message: message.clone(),
        reason: Some(match &failure.request_id {
            Some(request_id) => format!("{message} (Flitt request {request_id})"),
            None => message,
        }),
        attempt_status,
        connector_transaction_id: None,
        connector_response_reference_id: None,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
        connector_metadata: None,
    }
}

// ---------------------------------------------------------------------------
// Capture and reverse answers
// ---------------------------------------------------------------------------

/// The capture answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlittCaptureAnswer {
    pub order_id: String,
    #[serde(default, deserialize_with = "flexible_string")]
    pub capture_status: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub response_code: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub response_description: Option<String>,
}

impl FlittCaptureAnswer {
    /// `captured` is charged; a decline is a failed capture; anything else
    /// (Flitt still holding) is a capture in progress.
    pub fn attempt_status(&self) -> enums::AttemptStatus {
        match self.capture_status.as_deref() {
            Some("captured") => enums::AttemptStatus::Charged,
            Some("declined") | Some("failure") => enums::AttemptStatus::CaptureFailed,
            _ if self.response_code.is_some() => enums::AttemptStatus::CaptureFailed,
            _ => enums::AttemptStatus::CaptureInitiated,
        }
    }

    pub fn error(&self, http_code: u16) -> ErrorResponse {
        let message = self
            .response_description
            .clone()
            .unwrap_or_else(|| "Flitt declined the capture".to_string());
        ErrorResponse {
            status_code: http_code,
            code: self
                .response_code
                .clone()
                .or_else(|| self.capture_status.clone())
                .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string()),
            message: message.clone(),
            reason: Some(message),
            attempt_status: Some(enums::AttemptStatus::CaptureFailed),
            connector_transaction_id: Some(self.order_id.clone()),
            connector_response_reference_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        }
    }
}

/// The reverse answer (refunds and hold releases).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlittReverseAnswer {
    pub order_id: String,
    pub reverse_status: FlittOrderStatus,
    #[serde(default, deserialize_with = "flexible_string")]
    pub reverse_id: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub reversal_amount: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub transaction_id: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub response_code: Option<String>,
    #[serde(default, deserialize_with = "flexible_string")]
    pub response_description: Option<String>,
}

impl FlittReverseAnswer {
    pub fn refund_status(&self) -> enums::RefundStatus {
        match self.reverse_status {
            FlittOrderStatus::Approved | FlittOrderStatus::Reversed => enums::RefundStatus::Success,
            FlittOrderStatus::Declined | FlittOrderStatus::Expired => enums::RefundStatus::Failure,
            FlittOrderStatus::Created
            | FlittOrderStatus::Processing
            | FlittOrderStatus::Unknown => enums::RefundStatus::Pending,
        }
    }

    pub fn void_status(&self) -> enums::AttemptStatus {
        match self.refund_status() {
            enums::RefundStatus::Success => enums::AttemptStatus::Voided,
            enums::RefundStatus::Failure => enums::AttemptStatus::VoidFailed,
            _ => enums::AttemptStatus::VoidInitiated,
        }
    }

    /// Flitt's id of the reversal, else the `reverse_id` that was sent.
    pub fn connector_refund_id(&self, sent_reverse_id: &str) -> String {
        self.transaction_id
            .clone()
            .or_else(|| self.reverse_id.clone())
            .unwrap_or_else(|| sent_reverse_id.to_string())
    }

    pub fn error(
        &self,
        http_code: u16,
        attempt_status: Option<enums::AttemptStatus>,
    ) -> ErrorResponse {
        let status = self.reverse_status.to_string();
        let message = self
            .response_description
            .clone()
            .unwrap_or_else(|| format!("Flitt answered the reversal with {status}"));
        ErrorResponse {
            status_code: http_code,
            code: self.response_code.clone().unwrap_or(status),
            message: message.clone(),
            reason: Some(message),
            attempt_status,
            connector_transaction_id: Some(self.order_id.clone()),
            connector_response_reference_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        }
    }
}

/// HTTP status given to a Flitt refusal of a refund *status* request, so the
/// router keeps the refund as it is instead of failing it. Flitt answers every
/// refusal with HTTP 200, and the router fails a refund on any 2xx error
/// during a refund sync; but a refused re-send (for example error 1000 once
/// the order is fully reversed by others) does not say this refund failed.
pub const REFUND_SYNC_REFUSAL_HTTP_CODE: u16 = 409;

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

/// The order a callback describes, read without checking its signature: only
/// to name the payment and pick the router's flow.
pub fn callback_order(body: &[u8]) -> Result<FlittOrder, error_stack::Report<ConnectorError>> {
    match protocol::read(body, None).change_context(ConnectorError::WebhookBodyDecodingFailed)? {
        FlittMessage::Enveloped { payload, .. } | FlittMessage::Flat { payload, .. } => {
            serde_json::from_value(payload)
                .change_context(ConnectorError::WebhookBodyDecodingFailed)
        }
        FlittMessage::Failure(_) => Err(report!(ConnectorError::WebhookBodyDecodingFailed)),
    }
}

/// Whether a callback may be applied as it is: a protocol 2.0 envelope whose
/// signature matches this account's payment key, about an order of this
/// account's Flitt merchant.
pub fn is_verified_callback(body: &[u8], auth: &FlittAuthType) -> bool {
    match protocol::read(body, Some(&auth.payment_key)) {
        Ok(FlittMessage::Enveloped {
            payload,
            signature_valid: true,
        }) => serde_json::from_value::<FlittOrder>(payload)
            .ok()
            .and_then(|order| order.merchant_id)
            .is_some_and(|merchant_id| merchant_id == auth.merchant_id.to_string()),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Flitt sends most values as strings, some as numbers (`response_code`,
/// `card_bin`, `payment_id`), and "" for nothing.
fn flexible_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| match value {
        serde_json::Value::String(text) if text.trim().is_empty() => None,
        serde_json::Value::String(text) => Some(text),
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }))
}

#[cfg(test)]
mod tests;
