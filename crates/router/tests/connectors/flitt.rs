//! Flitt connector tests against Flitt's public test merchant (docs.flitt.com,
//! Testing: merchant 1549901, payment key `test`; put them in the `[flitt]`
//! section of the file named by `CONNECTOR_AUTH_FILE_PATH`).
//!
//! A Flitt payment is finished by the payer on Flitt's own page or in their
//! bank, so these tests cover what the connector does without a payer:
//! creating card and bank orders, reading an unpaid order, and the refusals
//! of operations on it. Paid orders, 3-D Secure, refunds and callbacks are
//! covered by the end-to-end run through a router (see the PR).

use common_utils::types::MinorUnit;
use hyperswitch_domain_models::{
    payment_method_data::{BankRedirectData, PaymentMethodData},
    router_response_types::RedirectForm,
};
use router::types::{self, api, storage::enums};
use test_utils::connector_auth;

use crate::utils::{self, ConnectorActions};

#[derive(Clone, Copy)]
struct FlittTest;
impl ConnectorActions for FlittTest {}
impl utils::Connector for FlittTest {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Flitt;
        utils::construct_connector_data_old(
            Box::new(Flitt::new()),
            types::Connector::Flitt,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        utils::to_connector_auth_type(
            connector_auth::ConnectorAuthentication::new()
                .flitt
                .expect("Missing connector authentication configuration")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "flitt".to_string()
    }
}

static CONNECTOR: FlittTest = FlittTest {};

fn order_data(metadata: Option<serde_json::Value>) -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data: PaymentMethodData::BankRedirect(
            BankRedirectData::LocalBankRedirect {},
        ),
        amount: 150,
        minor_amount: MinorUnit::new(150),
        currency: enums::Currency::GEL,
        router_return_url: Some("https://hs.example.test/payments/redirect/response".to_string()),
        webhook_url: Some("https://hs.example.test/webhooks/merchant_1/mca_1".to_string()),
        metadata,
        ..utils::PaymentAuthorizeType::default().0
    })
}

fn order_id(response: &types::PaymentsAuthorizeRouterData) -> String {
    utils::get_connector_transaction_id(response.response.clone()).expect("an order id")
}

#[actix_web::test]
async fn a_card_order_waits_for_the_payer_on_flitts_page() {
    let response = CONNECTOR
        .authorize_payment(order_data(None), None)
        .await
        .expect("Authorize response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
    match response.response.as_ref().expect("an order") {
        types::PaymentsResponseData::TransactionResponse {
            redirection_data,
            connector_metadata,
            ..
        } => {
            assert!(connector_metadata.is_none());
            match redirection_data.as_ref() {
                Some(RedirectForm::Form {
                    endpoint,
                    form_fields,
                    ..
                }) => {
                    assert!(endpoint.starts_with("https://pay.flitt.com/"), "{endpoint}");
                    assert!(form_fields.contains_key("token"));
                }
                other => panic!("{other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

#[actix_web::test]
async fn a_bank_order_hands_over_a_link_and_no_redirect() {
    let response = CONNECTOR
        .authorize_payment(
            order_data(Some(serde_json::json!({ "flitt_bank": "x" }))),
            None,
        )
        .await
        .expect("Authorize response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
    match response.response.as_ref().expect("an order") {
        types::PaymentsResponseData::TransactionResponse {
            redirection_data,
            connector_metadata,
            ..
        } => {
            assert!(redirection_data.is_none());
            let metadata = connector_metadata.clone().expect("the bank link");
            assert!(metadata["qr_code_url"]
                .as_str()
                .is_some_and(|url| url.starts_with("https://")));
            assert!(metadata["image_data_url"]
                .as_str()
                .is_some_and(|url| url.starts_with("data:image/png")));
        }
        other => panic!("{other:?}"),
    }
}

#[actix_web::test]
async fn an_unknown_bank_is_refused_before_flitt_is_called() {
    let response = CONNECTOR
        .authorize_payment(
            order_data(Some(serde_json::json!({ "flitt_bank": "TBC" }))),
            None,
        )
        .await;
    assert!(response.is_err());
}

#[actix_web::test]
async fn an_unpaid_order_still_waits_for_the_payer() {
    let authorized = CONNECTOR
        .authorize_payment(order_data(None), None)
        .await
        .expect("Authorize response");
    let response = CONNECTOR
        .sync_payment(
            Some(types::PaymentsSyncData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(order_id(
                    &authorized,
                )),
                ..Default::default()
            }),
            None,
        )
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending);
}

#[actix_web::test]
async fn an_unknown_order_is_reported_without_changing_the_payment() {
    let response = CONNECTOR
        .sync_payment(
            Some(types::PaymentsSyncData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(format!(
                    "drp_missing_{}",
                    common_utils::generate_uuid_v4()
                )),
                ..Default::default()
            }),
            None,
        )
        .await
        .expect("PSync response");
    let error = response
        .response
        .expect_err("Flitt does not know the order");
    assert_eq!(error.code, "1018");
    assert_eq!(error.attempt_status, Some(response.status));
}

#[actix_web::test]
async fn an_unpaid_order_cannot_be_refunded() {
    let authorized = CONNECTOR
        .authorize_payment(order_data(None), None)
        .await
        .expect("Authorize response");
    let response = CONNECTOR
        .refund_payment(
            order_id(&authorized),
            Some(types::RefundsData {
                refund_amount: 150,
                minor_refund_amount: MinorUnit::new(150),
                currency: enums::Currency::GEL,
                ..utils::PaymentRefundType::default().0
            }),
            None,
        )
        .await
        .expect("Refund response");
    let error = response.response.expect_err("nothing to reverse");
    assert_eq!(error.code, "1000");
}

#[actix_web::test]
async fn a_currency_the_merchant_lacks_leaves_the_payment_payable() {
    let response = CONNECTOR
        .authorize_payment(
            order_data(None).map(|data| types::PaymentsAuthorizeData {
                currency: enums::Currency::JPY,
                ..data
            }),
            None,
        )
        .await
        .expect("Authorize response");
    assert_eq!(response.status, enums::AttemptStatus::PaymentMethodAwaited);
    let error = response.response.expect_err("Flitt refuses the currency");
    assert_eq!(
        error.attempt_status,
        Some(enums::AttemptStatus::PaymentMethodAwaited)
    );
}
