#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_from_request_uses_wallet_and_payment_hash() {
        let body = serde_json::json!({
            "query": "mutation LnInvoiceCreateOnBehalfOfRecipient { lnInvoiceCreateOnBehalfOfRecipient { invoice { paymentHash } } }",
            "variables": { "input": { "recipientWalletId": "btc-wallet-error" } }
        });

        assert_eq!(scenario_from_request(&body), MockScenario::GraphqlError);
    }
}
