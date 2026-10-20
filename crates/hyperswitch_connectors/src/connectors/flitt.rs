//! Flitt (pay.flitt.com) connector.
//!
//! Flows: Authorize (create an order on Flitt's checkout: the card page, which
//! also carries Apple Pay and Google Pay and shows 3-D Secure inside itself, or
//! an open-banking bank link), PSync (order status), Capture and Void of a
//! card hold, Refund and refund sync (reverse), and Flitt's server callback as
//! an incoming webhook. Card data never reaches Hyperswitch: the payer enters
//! it on Flitt's page.
//!
//! Every request is signed with the merchant's payment key in Flitt's
//! protocol 2.0 envelope, and so is every answer and callback about an order
//! created that way (see [`protocol`]). Flitt answers refusals with HTTP 200
//! and `response_status: failure`, so each flow reads the body, not the HTTP
//! status, to tell an answer from a refusal.

pub mod protocol;
pub mod transformers;

use std::sync::LazyLock;

use common_enums::enums;
use common_utils::{
    errors::CustomResult,
    ext_traits::ValueExt,
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, MinorUnit, MinorUnitForConnector},
};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{Authorize, Capture, PSync, PaymentMethodToken, Session, SetupMandate, Void},
        refunds::{Execute, RSync},
    },
    router_request_types::{
        AccessTokenRequestData, PaymentMethodTokenizationData, PaymentsAuthorizeData,
        PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData, PaymentsSyncData,
        RefundsData, SetupMandateRequestData,
    },
    router_response_types::{
        ConnectorInfo, PaymentMethodDetails, PaymentsResponseData, RefundsResponseData,
        SupportedPaymentMethods, SupportedPaymentMethodsExt,
    },
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsCaptureRouterData,
        PaymentsSyncRouterData, RefundSyncRouterData, RefundsRouterData,
    },
};
use hyperswitch_interfaces::{
    api::{
        self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorSpecifications,
        ConnectorValidation,
    },
    configs::Connectors,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::{self, Response},
    webhooks,
};
use hyperswitch_masking::{Maskable, Secret};
use transformers as flitt;

use crate::{constants::headers, utils};

const CHECKOUT_URL_PATH: &str = "/api/checkout/url";
const STATUS_PATH: &str = "/api/status/order_id";
const CAPTURE_PATH: &str = "/api/capture/order_id";
const REVERSE_PATH: &str = "/api/reverse/order_id";

#[derive(Clone)]
pub struct Flitt {
    amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
}

impl Flitt {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &MinorUnitForConnector,
        }
    }

    /// A signed protocol 2.0 request body for `params`.
    fn signed_body<T: serde::Serialize>(
        auth_type: &ConnectorAuthType,
        params: &T,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let auth = flitt::FlittAuthType::try_from(auth_type)?;
        let request = protocol::encode_request(&auth.payment_key, params)?;
        Ok(RequestContent::Json(Box::new(request)))
    }

    /// Reads a Flitt answer: `Ok(payload)` for an answer (whose signature, if
    /// any, matched), `Err(failure)` for a refusal.
    fn read_answer(
        auth_type: &ConnectorAuthType,
        res: &Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<Result<serde_json::Value, protocol::FlittFailure>, errors::ConnectorError>
    {
        let auth = flitt::FlittAuthType::try_from(auth_type)?;
        let answer = protocol::read_answer(&res.response, &auth.payment_key)?;
        match &answer {
            Ok(payload) => {
                event_builder.map(|event| event.set_response_body(payload));
                router_env::logger::info!(connector_response=?payload);
            }
            Err(failure) => {
                event_builder.map(|event| event.set_response_body(failure));
                router_env::logger::info!(connector_response=?failure);
            }
        }
        Ok(answer)
    }

    /// The Flitt order of a payment: the order id Authorize returned, else the
    /// attempt reference it was created with (they are the same value).
    fn order_id(connector_transaction_id: Option<String>, reference_id: &str) -> String {
        connector_transaction_id
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| reference_id.to_string())
    }

    fn reverse_request(
        &self,
        auth_type: &ConnectorAuthType,
        order_id: String,
        amount: MinorUnit,
        currency: enums::Currency,
        reverse_id: String,
        comment: Option<String>,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let auth = flitt::FlittAuthType::try_from(auth_type)?;
        let amount = utils::convert_amount(self.amount_converter, amount, currency)?;
        Self::signed_body(
            auth_type,
            &flitt::FlittReverseRequest {
                merchant_id: auth.merchant_id,
                order_id,
                amount,
                currency,
                reverse_id,
                comment,
            },
        )
    }

    /// The refund answer, for Execute and RSync alike (RSync re-sends the
    /// same reverse). `refusal_http_code` is the HTTP status a refusal is
    /// reported with (see `transformers::REFUND_SYNC_REFUSAL_HTTP_CODE`).
    fn refund_response<F: Clone>(
        data: &RefundsRouterData<F>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
        refusal_http_code: u16,
    ) -> CustomResult<RefundsRouterData<F>, errors::ConnectorError> {
        let sent_reverse_id = flitt::reverse_id(&data.request.refund_id);
        let response = match Self::read_answer(&data.connector_auth_type, &res, event_builder)? {
            Err(failure) => Err(flitt::failure_error(&failure, refusal_http_code, None)),
            Ok(payload) => {
                let answer: flitt::FlittReverseAnswer =
                    payload
                        .parse_value("FlittReverseAnswer")
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                match answer.refund_status() {
                    enums::RefundStatus::Failure => Err(answer.error(res.status_code, None)),
                    refund_status => Ok(RefundsResponseData {
                        connector_refund_id: answer.connector_refund_id(&sent_reverse_id),
                        refund_status,
                    }),
                }
            }
        };
        Ok(RouterData {
            response,
            ..data.clone()
        })
    }
}

impl api::Payment for Flitt {}
impl api::PaymentSession for Flitt {}
impl api::ConnectorAccessToken for Flitt {}
impl api::MandateSetup for Flitt {}
impl api::PaymentAuthorize for Flitt {}
impl api::PaymentSync for Flitt {}
impl api::PaymentCapture for Flitt {}
impl api::PaymentVoid for Flitt {}
impl api::Refund for Flitt {}
impl api::RefundExecute for Flitt {}
impl api::RefundSync for Flitt {}
impl api::PaymentToken for Flitt {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Flitt
{
    // Not Implemented (R)
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Flitt
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        _req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Flitt authenticates the signature inside the body; no auth header.
        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.get_content_type().to_string().into(),
            ),
            (
                headers::ACCEPT.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
        ])
    }
}

impl ConnectorCommon for Flitt {
    fn id(&self) -> &'static str {
        "flitt"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.flitt.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Validate the credentials eagerly; nothing is sent as a header.
        flitt::FlittAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(Vec::new())
    }

    /// A non-2xx answer: Flitt itself answers refusals with HTTP 200, so this
    /// is a proxy or an outage; its body is read as a refusal when it is one.
    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let failure = match protocol::read(&res.response, None) {
            Ok(protocol::FlittMessage::Failure(failure)) => failure,
            _ => protocol::FlittFailure {
                error_code: None,
                error_message: Some(format!("Flitt answered HTTP {}", res.status_code)),
                request_id: None,
            },
        };
        event_builder.map(|event| event.set_error_response_body(&failure));
        router_env::logger::info!(connector_response=?failure);
        Ok(flitt::failure_error(&failure, res.status_code, None))
    }
}

impl ConnectorValidation for Flitt {
    /// A payment can always be looked up: when Authorize left no order id,
    /// the attempt reference is the Flitt order id.
    fn validate_psync_reference_id(
        &self,
        _data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: enums::AttemptStatus,
        _connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }
}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Flitt {}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Flitt {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Flitt {
    fn build_request(
        &self,
        _req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Err(
            errors::ConnectorError::NotImplemented("Setup Mandate flow for Flitt".to_string())
                .into(),
        )
    }
}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Flitt {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}{CHECKOUT_URL_PATH}", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;
        let connector_router_data = flitt::FlittRouterData::from((amount, req));
        let order = flitt::FlittOrderRequest::try_from(&connector_router_data)?;
        Self::signed_body(&req.connector_auth_type, &order)
    }

    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(types::PaymentsAuthorizeType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsAuthorizeType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        match Self::read_answer(&data.connector_auth_type, &res, event_builder)? {
            // No order was created: the payment stays payable.
            Err(failure) => Ok(RouterData {
                status: flitt::REFUSED_ORDER_ATTEMPT_STATUS,
                response: Err(flitt::failure_error(
                    &failure,
                    res.status_code,
                    Some(flitt::REFUSED_ORDER_ATTEMPT_STATUS),
                )),
                ..data.clone()
            }),
            Ok(payload) => {
                let checkout: flitt::FlittCheckout = payload
                    .parse_value("FlittCheckout")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                let metadata = data.request.metadata.as_ref();
                let bank = flitt::bank_from_metadata(metadata)?;
                let lifetime = flitt::lifetime_from_metadata(metadata)?;
                let expires_at_ms = (common_utils::date_time::now().assume_utc().unix_timestamp()
                    + i64::from(lifetime))
                    * 1000;
                let response = flitt::checkout_response(
                    &checkout,
                    bank,
                    &data.connector_request_reference_id,
                    expires_at_ms,
                )?;
                Ok(RouterData {
                    status: enums::AttemptStatus::AuthenticationPending,
                    response: Ok(response),
                    ..data.clone()
                })
            }
        }
    }

    /// A create-order answered with a 4xx created no order (Flitt itself
    /// answers with 200), so the payment stays payable.
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let refused = (400..=499).contains(&res.status_code);
        let mut error = self.build_error_response(res, event_builder)?;
        if refused {
            error.attempt_status = Some(flitt::REFUSED_ORDER_ATTEMPT_STATUS);
        }
        Ok(error)
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Flitt {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}{STATUS_PATH}", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let auth = flitt::FlittAuthType::try_from(&req.connector_auth_type)?;
        let order_id = Self::order_id(
            req.request
                .connector_transaction_id
                .get_connector_transaction_id()
                .ok(),
            &req.connector_request_reference_id,
        );
        Self::signed_body(
            &req.connector_auth_type,
            &flitt::FlittOrderReference {
                merchant_id: auth.merchant_id,
                order_id,
            },
        )
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsSyncType::get_headers(self, req, connectors)?)
                .set_body(types::PaymentsSyncType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    /// Also reads a verified callback (the router hands its body here), so
    /// the stale-callback rule of `transformers::attempt_status` applies to
    /// both. The attempt's connector metadata (a bank link) is kept.
    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
        match Self::read_answer(&data.connector_auth_type, &res, event_builder)? {
            // A refused status request says nothing about the payment: keep it.
            Err(failure) => Ok(RouterData {
                response: Err(flitt::failure_error(
                    &failure,
                    res.status_code,
                    Some(data.status),
                )),
                ..data.clone()
            }),
            Ok(payload) => {
                let order: flitt::FlittOrder = payload
                    .parse_value("FlittOrder")
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                let status = flitt::attempt_status(&order, data.status);
                let response = if utils::is_payment_failure(status) {
                    Err(flitt::order_error(&order, res.status_code))
                } else {
                    Ok(flitt::order_response(
                        &order,
                        data.request.connector_meta.clone(),
                    ))
                };
                Ok(RouterData {
                    status,
                    response,
                    ..data.clone()
                })
            }
        }
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Flitt {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}{CAPTURE_PATH}", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let auth = flitt::FlittAuthType::try_from(&req.connector_auth_type)?;
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount_to_capture,
            req.request.currency,
        )?;
        Self::signed_body(
            &req.connector_auth_type,
            &flitt::FlittCaptureRequest {
                merchant_id: auth.merchant_id,
                order_id: req.request.connector_transaction_id.clone(),
                amount,
                currency: req.request.currency,
            },
        )
    }

    fn build_request(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsCaptureType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsCaptureType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsCaptureType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsCaptureRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCaptureRouterData, errors::ConnectorError> {
        match Self::read_answer(&data.connector_auth_type, &res, event_builder)? {
            Err(failure) => Ok(RouterData {
                response: Err(flitt::failure_error(&failure, res.status_code, None)),
                ..data.clone()
            }),
            Ok(payload) => {
                let answer: flitt::FlittCaptureAnswer =
                    payload
                        .parse_value("FlittCaptureAnswer")
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                let status = answer.attempt_status();
                let response = if status == enums::AttemptStatus::CaptureFailed {
                    Err(answer.error(res.status_code))
                } else {
                    Ok(flitt::transaction_response(&answer.order_id, None))
                };
                Ok(RouterData {
                    status,
                    response,
                    ..data.clone()
                })
            }
        }
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

/// Releases a card hold (an order created with `preauth=Y` and not captured)
/// with a full reverse. Flitt refuses a partial reverse of a hold and has no
/// way to cancel an order that is not paid yet, so the router's cancel of a
/// payment waiting for the payer (requires_customer_action) does not reach
/// Flitt: such an order expires at the end of its lifetime.
impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Flitt {
    fn get_headers(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}{REVERSE_PATH}", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &PaymentsCancelRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount =
            req.request
                .minor_amount
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "amount".into(),
                })?;
        let currency =
            req.request
                .currency
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "currency".into(),
                })?;
        let order_id = req.request.connector_transaction_id.clone();
        self.reverse_request(
            &req.connector_auth_type,
            order_id.clone(),
            amount,
            currency,
            flitt::void_reverse_id(&order_id),
            flitt::reverse_comment(req.request.cancellation_reason.as_deref()),
        )
    }

    fn build_request(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsVoidType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsVoidType::get_headers(self, req, connectors)?)
                .set_body(types::PaymentsVoidType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsCancelRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCancelRouterData, errors::ConnectorError> {
        match Self::read_answer(&data.connector_auth_type, &res, event_builder)? {
            Err(failure) => Ok(RouterData {
                response: Err(flitt::failure_error(&failure, res.status_code, None)),
                ..data.clone()
            }),
            Ok(payload) => {
                let answer: flitt::FlittReverseAnswer =
                    payload
                        .parse_value("FlittReverseAnswer")
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                let status = answer.void_status();
                let response = if status == enums::AttemptStatus::VoidFailed {
                    Err(answer.error(res.status_code, Some(status)))
                } else {
                    Ok(flitt::transaction_response(
                        &answer.order_id,
                        answer.transaction_id.clone(),
                    ))
                };
                Ok(RouterData {
                    status,
                    response,
                    ..data.clone()
                })
            }
        }
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

/// A refund is a Flitt reverse with the Hyperswitch refund id as Flitt's
/// idempotency key (`reverse_id`), so a repeated refund request reverses
/// once. Flitt answers synchronously; full and repeated partial refunds are
/// allowed up to the charged amount.
impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Flitt {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}{REVERSE_PATH}", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        self.reverse_request(
            &req.connector_auth_type,
            req.request.connector_transaction_id.clone(),
            req.request.minor_refund_amount,
            req.request.currency,
            flitt::reverse_id(&req.request.refund_id),
            flitt::reverse_comment(req.request.reason.as_deref()),
        )
    }

    fn build_request(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::RefundExecuteType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundExecuteType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::RefundExecuteType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    /// A refusal (HTTP 200 with an error code) fails the refund: Flitt did
    /// not reverse anything.
    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError> {
        let refusal_http_code = res.status_code;
        Self::refund_response(data, event_builder, res, refusal_http_code)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

/// Flitt has no per-reversal status call, and its order status only sums the
/// reversals. The documented way to learn the outcome of a reverse is to send
/// it again with the same `reverse_id` and amount: Flitt answers with the
/// reversal it already made (checked on the test merchant: same transaction
/// id, one reversal), or makes it if the first request never arrived, which
/// is what the pending refund asked for.
impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Flitt {
    fn get_headers(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}{REVERSE_PATH}", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        self.reverse_request(
            &req.connector_auth_type,
            req.request.connector_transaction_id.clone(),
            req.request.minor_refund_amount,
            req.request.currency,
            flitt::reverse_id(&req.request.refund_id),
            flitt::reverse_comment(req.request.reason.as_deref()),
        )
    }

    fn build_request(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::RefundSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundSyncType::get_headers(self, req, connectors)?)
                .set_body(types::RefundSyncType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    /// A refusal of the re-sent reverse leaves the refund as it is
    /// (`transformers::REFUND_SYNC_REFUSAL_HTTP_CODE`).
    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        Self::refund_response(
            data,
            event_builder,
            res,
            flitt::REFUND_SYNC_REFUSAL_HTTP_CODE,
        )
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

/// Flitt's server callback, POSTed to the order's `server_callback_url` (the
/// router's webhook URL for the merchant connector account) on every state
/// change; with Flitt's default `delayed=Y` one order can send several.
///
/// Orders are created in protocol 2.0, whose callback is an envelope signed
/// over its whole JSON text with the payment key. Such a callback, for this
/// account's Flitt merchant, is verified, and the router applies the order
/// state in it (through PSync's `handle_response`, which checks the signature
/// again). Anything else, a flat 1.0.1 callback included (its signature does
/// not bind values to names), is unverified: the router then asks Flitt for
/// the order's status and uses that answer, so a forged or re-labelled
/// callback costs one status request and changes nothing.
#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Flitt {
    async fn verify_webhook_source(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        connector_account_details: common_utils::crypto::Encryptable<Secret<serde_json::Value>>,
        _connector_name: &str,
    ) -> CustomResult<bool, errors::ConnectorError> {
        let auth_type: ConnectorAuthType = connector_account_details
            .parse_value("ConnectorAuthType")
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
        let auth = flitt::FlittAuthType::try_from(&auth_type)
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
        Ok(flitt::is_verified_callback(request.body, &auth))
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let order = flitt::callback_order(request.body)
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)?;
        Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
            api_models::payments::PaymentIdType::ConnectorTransactionId(order.order_id),
        ))
    }

    fn get_webhook_event_type(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _context: Option<&webhooks::WebhookContext>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        let order = flitt::callback_order(request.body)
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;
        Ok(flitt::webhook_event(&order))
    }

    /// The callback as PSync's `handle_response` reads it: `{"response":
    /// <the callback>}`, unchanged, so its signature can be checked there.
    fn get_webhook_resource_object(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError>
    {
        let body: serde_json::Value = serde_json::from_slice(request.body)
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;
        let root = protocol::unwrap_root(&body).clone();
        if !root.is_object() {
            return Err(report!(
                errors::ConnectorError::WebhookResourceObjectNotFound
            ));
        }
        Ok(Box::new(serde_json::json!({ "response": root })))
    }
}

static FLITT_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let mut supported = SupportedPaymentMethods::new();
    // Flitt's checkout page (cards with 3-D Secure, Apple Pay, Google Pay) or
    // a bank's open-banking link, both reached through one redirect-type
    // method; the bank comes from the payment metadata (`flitt_bank`).
    supported.add(
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::LocalBankRedirect,
        PaymentMethodDetails {
            mandates: enums::FeatureStatus::NotSupported,
            refunds: enums::FeatureStatus::Supported,
            supported_capture_methods: vec![
                enums::CaptureMethod::Automatic,
                enums::CaptureMethod::Manual,
            ],
            specific_features: None,
        },
    );
    supported
});

static FLITT_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Flitt",
    description: "Flitt is a payment gateway in Georgia with a checkout page for cards (3-D Secure), Apple Pay and Google Pay, and open-banking payments from TBC, Bank of Georgia, Credo and Liberty, in GEL",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Beta,
};

static FLITT_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 1] = [enums::EventClass::Payments];

impl ConnectorSpecifications for Flitt {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&FLITT_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*FLITT_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&FLITT_SUPPORTED_WEBHOOK_FLOWS)
    }
}

#[cfg(test)]
mod tests;
