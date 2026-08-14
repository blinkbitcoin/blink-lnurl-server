//! axum listener + handler for the federated GraphQL subgraph. Runs on a
//! separate, non-ingress port; Apollo Router forwards the gateway-minted JWT.

use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{Router, http::HeaderMap, routing::post};
use tracing::{debug, info, warn};

use super::auth::{AuthSubject, GatewayAuthState, validate_gateway_token};
use super::{LnurlSchema, schema};
use crate::state::State;

/// Shared state for the graphql router: the federation schema plus the gateway
/// JWKS auth state. `auth` is `None` when the JWKS source is unconfigured; the
/// handler then fails closed for the mutation.
pub struct GraphqlServerState<DB>
where
    DB: crate::repository::LnurlRepository
        + crate::webhooks::WebhookRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub schema: LnurlSchema<DB>,
    pub auth: Option<GatewayAuthState>,
}

impl<DB> Clone for GraphqlServerState<DB>
where
    DB: crate::repository::LnurlRepository
        + crate::webhooks::WebhookRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    fn clone(&self) -> Self {
        Self {
            schema: self.schema.clone(),
            auth: self.auth.clone(),
        }
    }
}

pub fn router<DB>(state: State<DB>, auth: Option<GatewayAuthState>) -> Router
where
    DB: crate::repository::LnurlRepository
        + crate::webhooks::WebhookRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let gql_state = GraphqlServerState {
        schema: schema(Some(state)),
        auth,
    };
    Router::new()
        .route("/graphql", post(graphql_handler::<DB>))
        .with_state(gql_state)
}

pub async fn serve<DB>(addr: core::net::SocketAddr, router: Router) -> Result<(), anyhow::Error>
where
    DB: crate::repository::LnurlRepository
        + crate::webhooks::WebhookRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    info!(address = %addr, "starting GraphQL subgraph listener");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router.into_make_service()).await?;
    Ok(())
}

async fn graphql_handler<DB>(
    axum::extract::State(gql): axum::extract::State<GraphqlServerState<DB>>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse
where
    DB: crate::repository::LnurlRepository
        + crate::webhooks::WebhookRepository
        + Clone
        + Send
        + Sync
        + 'static,
{
    let req = req.into_inner();

    let subject = match extract_auth_subject(gql.auth.as_ref(), &headers) {
        Ok(subject) => subject,
        Err(e) => {
            warn!("graphql auth failed: {e}");
            // Reject the request outright: an invalid/absent credential cannot
            // be treated as anonymous, since anonymous must come from the
            // trusted signed gateway token, not from a client simply omitting
            // a header.
            let response =
                async_graphql::Response::from_errors(vec![async_graphql::ServerError::new(
                    "unauthenticated",
                    None,
                )]);
            return GraphQLResponse::from(response);
        }
    };

    gql.schema.execute(req.data(subject)).await.into()
}

fn extract_auth_subject(
    auth: Option<&GatewayAuthState>,
    headers: &HeaderMap,
) -> Result<AuthSubject, String> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| "missing bearer token".to_string())?;

    let auth = auth.ok_or_else(|| "gateway auth not configured".to_string())?;

    validate_gateway_token(auth, token).map_err(|e| {
        debug!("gateway token invalid: {e}");
        "invalid token".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{providers::ProviderRegistry, sqlite};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::{collections::HashSet, sync::Arc};
    use tokio::sync::{RwLock, watch};

    // Regression guard for the listener-lifecycle bug: the subgraph router must
    // actually accept connections and serve responses once bound.
    #[tokio::test]
    async fn graphql_listener_accepts_connections() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("sqlite pool");
        sqlite::run_migrations(&pool).await.expect("migrations");
        let repository = sqlite::LnurlRepository::new(pool);

        let spark_client = spark_client::Client::new(spark_client::ClientConfig::new(
            spark_client::Network::Regtest,
            [7_u8; 32],
        ))
        .await
        .expect("spark client");
        let (invoice_paid_trigger, _rx) = watch::channel(());
        let state = State {
            db: repository,
            spark_client: spark_client.clone(),
            providers: Arc::new(ProviderRegistry::new(spark_client, None, None, true, true)),
            internal_auth: None,
            scheme: "http".to_string(),
            callback_domain: None,
            min_sendable: 1_000,
            max_sendable: 4_000_000_000,
            include_spark_address: false,
            domains: Arc::new(RwLock::new(HashSet::new())),
            nostr_keys: None,
            ca_cert: None,
            crl_url: None,
            crl: HashSet::new(),
            invoice_paid_trigger,
            webhook_secret: "test-secret".to_string(),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let router = router(state, None);
        let server = tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .expect("serve");
        });

        // No gateway JWT => handler must reject with a GraphQL error body, which
        // proves the listener accepted the connection and ran the handler
        // (vs. connection-refused when the listener is not alive).
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/graphql"))
            .json(&serde_json::json!({"query": "{ __typename }"}))
            .send()
            .await
            .expect("request reaches the listener");
        assert!(resp.status().is_success());
        let body: serde_json::Value = resp.json().await.expect("json body");
        let message = body["errors"][0]["message"].as_str().unwrap_or("");
        assert_eq!(message, "unauthenticated");

        server.abort();
    }
}
