//! Keepz (Georgia) hosted-checkout connector.
//!
//! Flows: Authorize (create order -> redirect to `urlForQR`), PSync (order
//! status), Void (cancel), Refund (async refund/v2), RSync (order status) and
//! the payment callback as an incoming webhook.
//!
//! The callback is used as a trigger only. Keepz sends it as an encrypted,
//! unsigned envelope; the connector never opens it. Each order's
//! `callbackUri` carries the order id as a query parameter, the webhook
//! reads that id from the URL, reports the source as unverified, and the
//! router then asks Keepz for the order status (PSync) and uses that answer.

pub mod crypto;
pub mod transformers;

use std::sync::LazyLock;

use common_enums::enums;
use common_utils::{
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{
            Authorize, Capture, PSync, PaymentMethodToken, PreAuthorizeVoid, Session,
            SetupMandate, Void,
        },
        refunds::{Execute, RSync},
    },
    router_request_types::{
        AccessTokenRequestData, PaymentMethodTokenizationData, PaymentsAuthorizeData,
        PaymentsCancelData, PaymentsCaptureData, PaymentsPreAuthorizeCancelData,
        PaymentsSessionData, PaymentsSyncData,
        RefundsData, SetupMandateRequestData,
    },
    router_response_types::{
        ConnectorInfo, PaymentMethodDetails, PaymentsResponseData, RefundsResponseData,
        SupportedPaymentMethods, SupportedPaymentMethodsExt,
    },
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsCaptureRouterData,
        PaymentsPreAuthorizeCancelRouterData,
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
use serde::de::DeserializeOwned;
use transformers as keepz;

use crate::{constants::headers, types::ResponseRouterData, utils};

const ORDER_PATH: &str = "/api/integrator/order";
const ORDER_STATUS_PATH: &str = "/api/integrator/order/status";
const ORDER_CANCEL_PATH: &str = "/api/integrator/order/cancel";
const ORDER_REFUND_PATH: &str = "/api/integrator/order/refund/v2";

#[derive(Clone)]
pub struct Keepz {
    amount_converter: &'static (dyn AmountConvertor<Output = FloatMajorUnit> + Sync),
}

impl Keepz {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &FloatMajorUnitForConnector,
        }
    }

    /// Builds the encrypted envelope for a JSON body.
    fn envelope<T: serde::Serialize>(
        auth_type: &ConnectorAuthType,
        payload: &T,
    ) -> CustomResult<crypto::KeepzEnvelope, errors::ConnectorError> {
        let auth = keepz::KeepzAuthType::try_from(auth_type)?;
        crypto::encrypt_envelope(&auth.integrator_id, &auth.keepz_public_key, payload)
    }

    /// Builds `{base}{path}?identifier=..&encryptedData=..&encryptedKeys=..&aes=true`
    /// for the endpoints that take the envelope as query parameters.
    fn envelope_url(
        &self,
        connectors: &Connectors,
        path: &str,
        auth_type: &ConnectorAuthType,
        integrator_order_id: String,
    ) -> CustomResult<String, errors::ConnectorError> {
        let auth = keepz::KeepzAuthType::try_from(auth_type)?;
        let payload = keepz::KeepzOrderReference {
            integrator_id: auth.integrator_id.clone(),
            integrator_order_id,
        };
        let envelope = Self::envelope(auth_type, &payload)?;
        let query = serde_urlencoded::to_string(&envelope)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(format!("{}{path}?{query}", self.base_url(connectors)))
    }

    /// Parses a Keepz success body: decrypts the envelope with the integrator
    /// private key and deserializes the plaintext JSON.
    fn parse_encrypted<T: DeserializeOwned>(
        auth_type: &ConnectorAuthType,
        res: &Response,
        type_name: &'static str,
    ) -> CustomResult<T, errors::ConnectorError> {
        let auth = keepz::KeepzAuthType::try_from(auth_type)?;
        let envelope: crypto::KeepzEncryptedResponse = res
            .response
            .parse_struct("KeepzEncryptedResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        let plaintext = crypto::decrypt_envelope(&auth.integrator_private_key, &envelope)?;
        plaintext
            .as_slice()
            .parse_struct(type_name)
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)
    }
}

impl api::Payment for Keepz {}
impl api::PaymentSession for Keepz {}
impl api::ConnectorAccessToken for Keepz {}
impl api::MandateSetup for Keepz {}
impl api::PaymentAuthorize for Keepz {}
impl api::PaymentSync for Keepz {}
impl api::PaymentCapture for Keepz {}
impl api::PaymentVoid for Keepz {}
impl api::PaymentPreAuthorizeVoid for Keepz {}
impl api::Refund for Keepz {}
impl api::RefundExecute for Keepz {}
impl api::RefundSync for Keepz {}
impl api::PaymentToken for Keepz {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Keepz
{
    // Not Implemented (R)
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Keepz
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        _req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Identity travels inside the encrypted envelope; no auth header.
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

impl ConnectorCommon for Keepz {
    fn id(&self) -> &'static str {
        "keepz"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.keepz.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        // Validate credentials eagerly; nothing is sent as a header.
        keepz::KeepzAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(Vec::new())
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: keepz::KeepzErrorResponse = res
            .response
            .parse_struct("KeepzErrorResponse")
            .unwrap_or_default();

        event_builder.map(|i| i.set_error_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code(),
            message: response.message(),
            reason: response.message,
            attempt_status: None,
            connector_transaction_id: None,
            connector_response_reference_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        })
    }
}

impl ConnectorValidation for Keepz {
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

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Keepz {}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Keepz {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Keepz {
    fn build_request(
        &self,
        _req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Err(
            errors::ConnectorError::NotImplemented("Setup Mandate flow for Keepz".to_string())
                .into(),
        )
    }
}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Keepz {
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
        Ok(format!("{}{ORDER_PATH}", self.base_url(connectors)))
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
        let connector_router_data = keepz::KeepzRouterData::from((amount, req));
        let payload = keepz::KeepzCreateOrderRequest::try_from(&connector_router_data)?;
        let envelope = Self::envelope(&req.connector_auth_type, &payload)?;
        Ok(RequestContent::Json(Box::new(envelope)))
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
        let response: keepz::KeepzCreateOrderResponse =
            Self::parse_encrypted(&data.connector_auth_type, &res, "KeepzCreateOrderResponse")?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    /// A create-order Keepz refused (4xx) created no order, so the payment
    /// stays payable instead of failing: it can be confirmed again, for
    /// example without the bank Keepz did not accept
    /// (`transformers::refused_order_attempt_status`).
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let http_code = res.status_code;
        let mut error = self.build_error_response(res, event_builder)?;
        error.attempt_status = keepz::refused_order_attempt_status(http_code);
        Ok(error)
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Keepz {
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
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let integrator_order_id = req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        self.envelope_url(
            connectors,
            ORDER_STATUS_PATH,
            &req.connector_auth_type,
            integrator_order_id,
        )
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&types::PaymentsSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
        let response: keepz::KeepzOrderStatusResponse =
            Self::parse_encrypted(&data.connector_auth_type, &res, "KeepzOrderStatusResponse")?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Keepz {
    fn build_request(
        &self,
        _req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        // Keepz orders are captured automatically on payment.
        Err(errors::ConnectorError::NotSupported {
            message: "Capture".to_string(),
            connector: "Keepz",
        }
        .into())
    }
}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Keepz {
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
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        self.envelope_url(
            connectors,
            ORDER_CANCEL_PATH,
            &req.connector_auth_type,
            req.request.connector_transaction_id.clone(),
        )
    }

    fn build_request(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Delete)
                .url(&types::PaymentsVoidType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsVoidType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsCancelRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCancelRouterData, errors::ConnectorError> {
        let response: keepz::KeepzOrderStatusResponse =
            Self::parse_encrypted(&data.connector_auth_type, &res, "KeepzCancelResponse")?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

/// Cancelling a payment that waits for the payer (`requires_customer_action`).
/// The router uses this flow, not Void, for such a payment, and only because
/// Keepz declares `is_pre_authorize_cancel_supported`; without it the router
/// marked the payment cancelled locally and the Keepz order stayed payable.
/// Same Keepz call as Void (`DELETE /order/cancel`); only CANCELLED cancels
/// (`transformers::cancel_outcome`), and a refused or failed call leaves the
/// payment waiting for the payer.
impl ConnectorIntegration<PreAuthorizeVoid, PaymentsPreAuthorizeCancelData, PaymentsResponseData>
    for Keepz
{
    fn get_headers(
        &self,
        req: &PaymentsPreAuthorizeCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsPreAuthorizeCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        self.envelope_url(
            connectors,
            ORDER_CANCEL_PATH,
            &req.connector_auth_type,
            req.request.connector_transaction_id.clone(),
        )
    }

    fn build_request(
        &self,
        req: &PaymentsPreAuthorizeCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Delete)
                .url(&types::PaymentsPreAuthorizeVoidType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(types::PaymentsPreAuthorizeVoidType::get_headers(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsPreAuthorizeCancelRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsPreAuthorizeCancelRouterData, errors::ConnectorError> {
        let response: keepz::KeepzOrderStatusResponse =
            Self::parse_encrypted(&data.connector_auth_type, &res, "KeepzCancelResponse")?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        let (status, response) =
            keepz::cancel_outcome(&response, res.status_code, &data.connector_request_reference_id);
        Ok(RouterData {
            status,
            response,
            ..data.clone()
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let mut error = self.build_error_response(res, event_builder)?;
        error.attempt_status = Some(keepz::CANCEL_REFUSED_ATTEMPT_STATUS);
        Ok(error)
    }

    fn get_5xx_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let mut error = self.build_error_response(res, event_builder)?;
        error.attempt_status = Some(keepz::CANCEL_REFUSED_ATTEMPT_STATUS);
        Ok(error)
    }
}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Keepz {
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
        Ok(format!("{}{ORDER_REFUND_PATH}", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_refund_amount,
            req.request.currency,
        )?;
        let connector_router_data = keepz::KeepzRouterData::from((amount, req));
        let payload = keepz::KeepzRefundRequest::try_from(&connector_router_data)?;
        let envelope = Self::envelope(&req.connector_auth_type, &payload)?;
        Ok(RequestContent::Json(Box::new(envelope)))
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

    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError> {
        let response: keepz::KeepzOrderStatusResponse =
            Self::parse_encrypted(&data.connector_auth_type, &res, "KeepzRefundResponse")?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Keepz {
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
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Keepz has no refund ids; refund progress is read from the order.
        self.envelope_url(
            connectors,
            ORDER_STATUS_PATH,
            &req.connector_auth_type,
            req.request.connector_transaction_id.clone(),
        )
    }

    fn build_request(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&types::RefundSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        let response: keepz::KeepzOrderStatusResponse =
            Self::parse_encrypted(&data.connector_auth_type, &res, "KeepzRefundSyncResponse")?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

/// The Keepz callback is a trigger and nothing more.
///
/// Its body is the Keepz envelope sealed to the integrator's key, without a
/// signature. None of the functions below reads it: opening it here would put
/// the integrator private key on a public, unauthenticated endpoint (and make
/// that endpoint a decryption oracle), and nothing in it could be trusted
/// anyway. The order is named by the `ref` query parameter this connector
/// puts on every order's `callbackUri`; the event is always the same; and
/// because the source is reported as unverified, the router's payments flow
/// (`payments_incoming_webhook_flow`) calls the connector with
/// `CallConnectorAction::Trigger` and `force_sync: true`: a real order-status
/// request to Keepz, whose authenticated answer is the only thing that sets
/// the payment's status. Knowing an order id therefore buys an outsider one
/// status check of that order, which Keepz' unsigned callback always allowed.
#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Keepz {
    async fn verify_webhook_source(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        _connector_account_details: common_utils::crypto::Encryptable<Secret<serde_json::Value>>,
        _connector_name: &str,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(false)
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let order_id = keepz::callback_reference(&request.query_params)
            .ok_or(errors::ConnectorError::WebhookReferenceIdNotFound)?;
        Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
            api_models::payments::PaymentIdType::ConnectorTransactionId(order_id),
        ))
    }

    fn get_webhook_event_type(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _context: Option<&webhooks::WebhookContext>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        Ok(keepz::CALLBACK_EVENT)
    }

    fn get_webhook_resource_object(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError>
    {
        let integrator_order_id = keepz::callback_reference(&request.query_params)
            .ok_or(errors::ConnectorError::WebhookResourceObjectNotFound)?;
        Ok(Box::new(keepz::KeepzCallbackTrigger {
            integrator_order_id,
        }))
    }
}

static KEEPZ_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let mut supported = SupportedPaymentMethods::new();
    // Keepz is a hosted checkout (cards, open banking, QR) reached through a
    // single redirect; `LocalBankRedirect` is the closest generic method.
    supported.add(
        enums::PaymentMethod::BankRedirect,
        enums::PaymentMethodType::LocalBankRedirect,
        PaymentMethodDetails {
            mandates: enums::FeatureStatus::NotSupported,
            refunds: enums::FeatureStatus::Supported,
            supported_capture_methods: vec![enums::CaptureMethod::Automatic],
            specific_features: None,
        },
    );
    supported
});

static KEEPZ_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Keepz",
    description: "Keepz is a Georgian payment platform offering a hosted checkout for bank cards, open banking and QR payments in GEL",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Beta,
};

static KEEPZ_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 1] = [enums::EventClass::Payments];

impl ConnectorSpecifications for Keepz {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&KEEPZ_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*KEEPZ_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&KEEPZ_SUPPORTED_WEBHOOK_FLOWS)
    }

    /// Keepz only does `local_bank_redirect`, and every Keepz order can be
    /// cancelled while the payer has not finished (INITIAL, PROCESSING). The
    /// router then cancels through PreAuthorizeVoid, which asks Keepz.
    fn is_pre_authorize_cancel_supported(
        &self,
        _payment_method_type: Option<enums::PaymentMethodType>,
    ) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use api_models::{
        payments::PaymentIdType,
        webhooks::{IncomingWebhookEvent, ObjectReferenceId},
    };
    use hyperswitch_interfaces::webhooks::{IncomingWebhook as _, IncomingWebhookRequestDetails};

    use super::*;

    const ORDER_ID: &str = "a4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    const OTHER_ORDER_ID: &str = "b4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

    fn callback<'a>(
        headers: &'a actix_web::http::header::HeaderMap,
        query: &str,
        body: &'a [u8],
    ) -> IncomingWebhookRequestDetails<'a> {
        IncomingWebhookRequestDetails {
            method: http::Method::POST,
            uri: http::Uri::from_static("/webhooks/merchant_1/mca_1"),
            headers,
            body,
            query_params: query.to_string(),
        }
    }

    fn referenced_order(request: &IncomingWebhookRequestDetails<'_>) -> Option<String> {
        match Keepz::new().get_webhook_object_reference_id(request) {
            Ok(ObjectReferenceId::PaymentId(PaymentIdType::ConnectorTransactionId(id))) => {
                Some(id)
            }
            _ => None,
        }
    }

    fn event(request: &IncomingWebhookRequestDetails<'_>) -> Option<IncomingWebhookEvent> {
        Keepz::new().get_webhook_event_type(request, None).ok()
    }

    /// What Keepz really sends (its sealed envelope), what a forger would
    /// send (the documented plain JSON, claiming success for another order),
    /// and noise.
    fn bodies() -> Vec<&'static [u8]> {
        vec![
            br#"{"encryptedData":"AAAA","aes":true,"encryptedKeys":"BBBB"}"# as &[u8],
            br#"{"integratorOrderId":"b4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d","status":"SUCCESS","amount":1.5}"#
                as &[u8],
            b"integratorOrderId=b4b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d&status=SUCCESS" as &[u8],
            b"not json at all" as &[u8],
            b"" as &[u8],
        ]
    }

    #[test]
    fn the_order_comes_from_the_url_and_the_body_is_ignored() {
        let headers = actix_web::http::header::HeaderMap::new();
        let query = format!("ref={ORDER_ID}");
        for body in bodies() {
            let request = callback(&headers, &query, body);
            assert_eq!(referenced_order(&request), Some(ORDER_ID.to_string()));
            assert_eq!(event(&request), Some(IncomingWebhookEvent::PaymentIntentProcessing));
            // The logged content is the order id from the URL (its shape is
            // checked with `KeepzCallbackTrigger` in the transformers tests).
            assert!(Keepz::new().get_webhook_resource_object(&request).is_ok());
        }
    }

    #[test]
    fn a_body_cannot_name_the_order() {
        let headers = actix_web::http::header::HeaderMap::new();
        for body in bodies() {
            // No reference in the URL: nothing in the body supplies one.
            let request = callback(&headers, "", body);
            assert_eq!(referenced_order(&request), None);
            assert!(Keepz::new().get_webhook_resource_object(&request).is_err());
            // The event stays the same fixed trigger either way.
            assert_eq!(event(&request), Some(IncomingWebhookEvent::PaymentIntentProcessing));
        }
        // The URL names one order; a body naming another changes nothing.
        let request = callback(&headers, &format!("ref={ORDER_ID}"), bodies()[1]);
        assert_eq!(referenced_order(&request), Some(ORDER_ID.to_string()));
        assert_ne!(referenced_order(&request), Some(OTHER_ORDER_ID.to_string()));
    }

    #[test]
    fn a_malformed_reference_is_no_reference() {
        let headers = actix_web::http::header::HeaderMap::new();
        for query in [
            "ref=pay_abc_1".to_string(),
            format!("ref={}", ORDER_ID.to_uppercase()),
            format!("ref={ORDER_ID}&ref={OTHER_ORDER_ID}"),
            format!("order={ORDER_ID}"),
        ] {
            let request = callback(&headers, &query, b"");
            assert_eq!(referenced_order(&request), None, "{query}");
        }
    }

    /// `Connector::Keepz` is in the router's acknowledge-on-failure switch,
    /// so the answer to a failed callback is whatever this connector says.
    /// It says the same thing every time: a plain 200 for a callback that
    /// worked, for one whose reference names nothing, and for one whose
    /// processing failed. This pins the trait default, which Keepz relies on.
    #[test]
    fn every_callback_gets_the_same_acknowledgement() {
        let headers = actix_web::http::header::HeaderMap::new();
        for query in [format!("ref={ORDER_ID}"), "ref=nothing".to_string(), String::new()] {
            let request = callback(&headers, &query, b"");
            let acknowledged = |error_kind| {
                matches!(
                    Keepz::new().get_webhook_api_response(&request, error_kind, None),
                    Ok(hyperswitch_domain_models::api::WebhookResponse::StatusOk)
                )
            };
            assert!(acknowledged(None), "{query}");
            assert!(
                acknowledged(Some(webhooks::IncomingWebhookFlowError::ResourceNotFound)),
                "{query}"
            );
            assert!(
                acknowledged(Some(webhooks::IncomingWebhookFlowError::InternalError)),
                "{query}"
            );
        }
    }

    /// The source of a callback is never verified (`verify_webhook_source`
    /// answers false), and that must not be mandatory: the router would then
    /// reject every callback instead of running the status call.
    #[test]
    fn source_verification_is_not_mandatory() {
        assert!(!Keepz::new().is_webhook_source_verification_mandatory());
    }

    fn keepz_answer(status_code: u16, body: &'static [u8]) -> Response {
        Response {
            headers: None,
            response: bytes::Bytes::from_static(body),
            status_code,
        }
    }

    /// A refused create-order (Keepz' plain-JSON 4xx) keeps its code and
    /// message and leaves the payment waiting for a payment method; a server
    /// error at Keepz is left to the router's default handling.
    #[test]
    fn a_refused_create_order_keeps_the_payment_payable() {
        let refused = ConnectorIntegration::<Authorize, PaymentsAuthorizeData, PaymentsResponseData>::get_error_response(
            Keepz::new(),
            keepz_answer(
                400,
                br#"{"message":"You do not have permission","statusCode":6031,"exceptionGroup":3}"#,
            ),
            None,
        )
        .unwrap();
        assert_eq!(refused.status_code, 400);
        assert_eq!(refused.code, "6031");
        assert_eq!(refused.message, "You do not have permission");
        assert_eq!(
            refused.attempt_status,
            Some(enums::AttemptStatus::PaymentMethodAwaited)
        );

        let unreadable = ConnectorIntegration::<Authorize, PaymentsAuthorizeData, PaymentsResponseData>::get_error_response(
            Keepz::new(),
            keepz_answer(403, b"<html>blocked</html>"),
            None,
        )
        .unwrap();
        assert_eq!(
            unreadable.attempt_status,
            Some(enums::AttemptStatus::PaymentMethodAwaited)
        );

        // A refused status call keeps the router's own handling.
        let sync = ConnectorIntegration::<PSync, PaymentsSyncData, PaymentsResponseData>::get_error_response(
            Keepz::new(),
            keepz_answer(400, br#"{"message":"Order not found","statusCode":6005}"#),
            None,
        )
        .unwrap();
        assert_eq!(sync.attempt_status, None);
    }

    /// Without this the router cancels a payment that waits for the payer
    /// without asking Keepz (Void is only called from requires_capture), and
    /// the Keepz order stays payable.
    #[test]
    fn a_waiting_payment_is_cancelled_through_keepz() {
        for payment_method_type in [Some(enums::PaymentMethodType::LocalBankRedirect), None] {
            assert!(Keepz::new().is_pre_authorize_cancel_supported(payment_method_type));
        }
    }

    /// A cancel Keepz refuses (4xx) or cannot answer (5xx) leaves the payment
    /// waiting for the payer: never cancelled, never failed.
    #[test]
    fn a_refused_cancel_leaves_the_payment_waiting_for_the_payer() {
        let refused = <Keepz as ConnectorIntegration<
            PreAuthorizeVoid,
            PaymentsPreAuthorizeCancelData,
            PaymentsResponseData,
        >>::get_error_response(
            Keepz::new(),
            keepz_answer(
                400,
                br#"{"message":"Order can not be canceled","statusCode":6020,"exceptionGroup":3}"#,
            ),
            None,
        )
        .unwrap();
        assert_eq!(refused.code, "6020");
        assert_eq!(
            refused.attempt_status,
            Some(enums::AttemptStatus::AuthenticationPending)
        );
        let unreachable = <Keepz as ConnectorIntegration<
            PreAuthorizeVoid,
            PaymentsPreAuthorizeCancelData,
            PaymentsResponseData,
        >>::get_5xx_error_response(Keepz::new(), keepz_answer(502, b"Bad Gateway"), None)
        .unwrap();
        assert_eq!(unreachable.status_code, 502);
        assert_eq!(
            unreachable.attempt_status,
            Some(enums::AttemptStatus::AuthenticationPending)
        );
    }
}
