use crate::{
    providers::ProviderRegistry, repository::LnurlRepository, routes::LnurlServer, state::State,
};
use anyhow::anyhow;
use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    http::{Method, StatusCode},
    middleware,
    routing::{delete, get, post},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::Parser;
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, SqlitePool, sqlite::SqlitePoolOptions};
use std::collections::HashSet;
use std::str::FromStr;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::watch;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use x509_parser::prelude::{FromDer, X509Certificate};

mod auth;
mod domains;
mod error;
mod identifier;
mod internal_auth;
mod invoice_paid;
mod models;
mod postgresql;
mod providers;
mod repository;
mod routes;
mod sqlite;
mod state;
mod time;
mod user;
mod webhook_notify;
mod webhooks;
mod zap;

#[derive(Clone, Parser, Debug, Serialize, Deserialize)]
#[command(version, about, long_about = None)]
struct Args {
    /// Address the lnurl server will listen on.
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub address: core::net::SocketAddr,

    #[arg(long, default_value = "lnurl.conf")]
    pub config: PathBuf,

    /// Automatically apply migrations to the database.
    #[arg(long)]
    pub auto_migrate: bool,

    /// Connection string to the postgres database.
    #[arg(long, default_value = "")]
    pub db_url: String,

    /// Loglevel to use. Can be used to filter logs through the env filter
    /// format.
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Optional Spark network override.
    #[arg(long)]
    pub spark_network: Option<spark_client::Network>,

    /// Scheme prefix for lnurl urls.
    #[arg(long, default_value = "https")]
    pub scheme: String,

    /// Minimum amount (in millisatoshi) that can be sent in a lnurl payment.
    #[arg(long, default_value = "1000")]
    pub min_sendable: u64,

    /// Maximum amount (in millisatoshi) that can be sent in a lnurl payment.
    #[arg(long, default_value = "4000000000")]
    pub max_sendable: u64,

    /// Whether to include the spark address in the invoices generated.
    /// If included this can reduce fees for wallets that support it at the
    /// cost of privacy.
    #[cfg(feature = "dev")]
    #[arg(long, default_value = "false")]
    pub dev_dont_use_lnurl_include_spark_address: bool,

    /// List of domains that are allowed to use the lnurl server. Comma separated.
    /// These are in addition to any domains stored in the database. The configured
    /// domains here will be added to the database on startup.
    #[arg(long, default_value = "localhost:8080")]
    pub domains: String,

    /// Nostr private key for zaps. If not set, zap requests will be ignored.
    #[arg(long)]
    pub nsec: Option<String>,

    /// Base64 encoded DER format CA certificate without begin/end certificate markers.
    /// If set, the server will use this certificate to validate api keys.
    #[arg(long)]
    pub ca_cert: Option<String>,

    /// URL to fetch a comma-separated certificate revocation list from.
    #[arg(long)]
    pub crl_url: Option<String>,

    /// Domain for the webhook URL registered with the SSP.
    #[arg(long)]
    pub webhook_domain: Option<String>,

    /// Hex-encoded 32-byte seed used for SSP authentication.
    /// If not set, a random seed will be generated.
    #[arg(long)]
    pub ssp_auth_seed: Option<String>,

    /// Number of days to keep webhook deliveries (both succeeded and failed)
    /// for audit/debugging before they are cleaned up periodically.
    #[arg(long, default_value = "90")]
    pub webhook_delivery_ttl_days: u32,

    /// Optional Blink public GraphQL endpoint override.
    #[arg(long)]
    pub blink_graphql_endpoint: Option<String>,

    /// URL to fetch Blink Core internal-auth JWKS from at startup.
    #[arg(long)]
    pub internal_jwks_url: Option<String>,

    /// Local path to read Blink Core internal-auth JWKS from at startup.
    #[arg(long)]
    pub internal_jwks_path: Option<String>,

    /// Expected issuer for Blink Core internal-auth JWTs.
    #[arg(long)]
    pub internal_jwt_issuer: Option<String>,

    /// Expected audience for Blink Core internal-auth JWTs.
    #[arg(long)]
    pub internal_jwt_audience: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    let config_file = std::fs::canonicalize(&args.config).ok();
    let mut figment = Figment::new().merge(Serialized::defaults(args));
    if let Some(config_file) = &config_file {
        figment = figment.merge(Toml::file(config_file));
    }

    let args: Args = figment.merge(Env::prefixed("LNURL_")).extract()?;
    let (spark_network, blink_network, blink_graphql_endpoint) = resolve_runtime_config(
        std::env::var("DEPLOYMENT_ENV").ok().as_deref(),
        args.spark_network,
        args.blink_graphql_endpoint.as_deref(),
    )?;

    tracing_subscriber::registry()
        .with(EnvFilter::new(&args.log_level))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .init();

    if let Some(config_file) = &config_file {
        info!(
            "starting lnurl server with config file: {}",
            config_file.display()
        );
    } else {
        info!("starting lnurl server without config file");
    }

    if args.db_url.trim().to_lowercase().starts_with("postgres") {
        let pool = PgPool::connect(&args.db_url)
            .await
            .map_err(|e| anyhow!("failed to create connection pool: {e:?}"))?;

        if args.auto_migrate {
            debug!("running postgres database migrations");
            postgresql::run_migrations(&pool).await?;
            debug!("finished running postgres database migrations");
        } else {
            debug!("skipping postgres database migrations");
        }
        let repository = postgresql::LnurlRepository::new(pool);
        run_server(
            args,
            spark_network,
            blink_network,
            blink_graphql_endpoint,
            repository,
        )
        .await?;
    } else {
        // For in-memory databases, limit to 1 connection so all queries share
        // the same database. Each separate connection to `:memory:` creates its
        // own independent database.
        let pool = if args.db_url.contains(":memory:") {
            SqlitePoolOptions::new()
                .max_connections(1)
                .connect(&args.db_url)
                .await
        } else {
            SqlitePool::connect(&args.db_url).await
        }
        .map_err(|e| anyhow!("failed to create connection pool: {e:?}"))?;

        if args.auto_migrate {
            debug!("running sqlite database migrations");
            sqlite::run_migrations(&pool).await?;
            debug!("finished running sqlite database migrations");
        } else {
            debug!("skipping sqlite database migrations");
        }
        let repository = sqlite::LnurlRepository::new(pool);
        run_server(
            args,
            spark_network,
            blink_network,
            blink_graphql_endpoint,
            repository,
        )
        .await?;
    }

    Ok(())
}

fn parse_auth_seed(hex_str: Option<&str>) -> [u8; 32] {
    let Some(hex_str) = hex_str else {
        return rand::random();
    };
    let Ok(bytes) = hex::decode(hex_str) else {
        error!("invalid ssp_auth_seed hex, using random seed");
        return rand::random();
    };
    let Ok(seed) = bytes.try_into() else {
        error!("ssp_auth_seed must be 32 bytes, using random seed");
        return rand::random();
    };
    seed
}

fn build_blink_webhook_url(args: &Args) -> Result<String, anyhow::Error> {
    let Some(webhook_domain) = args.webhook_domain.as_deref() else {
        return Err(anyhow!(
            "LNURL_WEBHOOK_DOMAIN is required to create Blink invoice webhookUrl callbacks"
        ));
    };

    Ok(format!(
        "{}://{}/webhook/blink",
        args.scheme, webhook_domain
    ))
}

fn resolve_runtime_config(
    deployment_env: Option<&str>,
    configured_spark_network: Option<spark_client::Network>,
    configured_blink_graphql_endpoint: Option<&str>,
) -> Result<(spark_client::Network, &'static str, String), anyhow::Error> {
    let Some(deployment_env) = deployment_env
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(anyhow!(
            "DEPLOYMENT_ENV is required and must be one of: production, staging, local"
        ));
    };
    let configured_blink_graphql_endpoint = configured_blink_graphql_endpoint
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let (default_spark_network, blink_network, default_blink_graphql_endpoint) =
        match deployment_env {
            "production" => (
                spark_client::Network::Mainnet,
                "mainnet",
                blink_client::PRODUCTION_GRAPHQL_ENDPOINT.to_string(),
            ),
            "staging" => (
                // Spark staging stays on Regtest until Spark signet support is ready.
                spark_client::Network::Regtest,
                "signet",
                blink_client::STAGING_GRAPHQL_ENDPOINT.to_string(),
            ),
            "local" => (
                spark_client::Network::Regtest,
                "regtest",
                configured_blink_graphql_endpoint
                    .ok_or_else(|| {
                        anyhow!(
                            "LNURL_BLINK_GRAPHQL_ENDPOINT is required when DEPLOYMENT_ENV=local"
                        )
                    })?
                    .to_string(),
            ),
            unsupported => {
                return Err(anyhow!(
                    "unsupported DEPLOYMENT_ENV '{unsupported}'; expected one of: production, staging, local"
                ));
            }
        };

    let spark_network = configured_spark_network.unwrap_or(default_spark_network);
    let blink_graphql_endpoint = if deployment_env == "local" {
        default_blink_graphql_endpoint
    } else if let Some(blink_graphql_endpoint) = configured_blink_graphql_endpoint {
        blink_graphql_endpoint.to_string()
    } else {
        default_blink_graphql_endpoint
    };

    Ok((spark_network, blink_network, blink_graphql_endpoint))
}

#[allow(clippy::too_many_lines)]
async fn run_server<DB>(
    args: Args,
    spark_network: spark_client::Network,
    blink_network: &'static str,
    blink_graphql_endpoint: String,
    repository: DB,
) -> Result<(), anyhow::Error>
where
    DB: LnurlRepository + webhooks::WebhookRepository + Clone + Send + Sync + 'static,
{
    let blink_webhook_url = build_blink_webhook_url(&args)?;
    let auth_seed = parse_auth_seed(args.ssp_auth_seed.as_deref());
    info!(
        deployment_env_blink_network = blink_network,
        blink_graphql_endpoint = blink_graphql_endpoint,
        "resolved provider runtime configuration from DEPLOYMENT_ENV"
    );
    let spark_client =
        spark_client::Client::new(spark_client::ClientConfig::new(spark_network, auth_seed))
            .await?;

    let config_domains: Vec<String> = args
        .domains
        .split(',')
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    for domain in &config_domains {
        repository.add_domain(domain).await?;
        debug!("ensured domain '{}' exists in database", domain);
    }

    let domains = domains::start(repository.clone()).await?;

    let internal_auth = load_internal_auth_state(&args).await;

    let ca_cert = args
        .ca_cert
        .map(|ca_cert_str| {
            let raw_ca = BASE64_STANDARD
                .decode(ca_cert_str.trim())
                .map_err(|e| anyhow!("failed to decode base64 ca_cert: {e:?}"))?;
            let (_, ca_cert) = X509Certificate::from_der(&raw_ca)
                .map_err(|e| anyhow!("failed to parse ca certificate: {e:?}"))?;
            Ok::<_, anyhow::Error>(ca_cert.as_raw().to_vec())
        })
        .transpose()?;

    let crl: HashSet<String> = if let Some(url) = &args.crl_url {
        let client = reqwest::Client::new();
        let body = client
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("failed to fetch crl from {url}: {e:?}"))?
            .text()
            .await
            .map_err(|e| anyhow!("failed to read crl response body: {e:?}"))?;
        body.split(',').map(str::to_string).collect()
    } else {
        HashSet::new()
    };

    let nostr_keys = args
        .nsec
        .map(|nsec| {
            let keys = nostr::Keys::from_str(&nsec)
                .map_err(|e| anyhow!("failed to parse nsec key: {e:?}"))?;
            Ok::<_, anyhow::Error>(keys)
        })
        .transpose()?;

    // Create watch channel for triggering background processing
    let (invoice_paid_trigger, invoice_paid_rx) = watch::channel(());

    // Create a shared HTTP client for webhook delivery. reqwest's default pool
    // settings keep connections warm and HTTP/2 multiplexes requests per host.
    let http_client = reqwest::Client::new();

    // Load webhook endpoint configs (domain → {url, secret}) and start
    // a background refresher that keeps them in sync with the database.
    let webhook_config_cache = webhooks::config::start(repository.clone()).await?;

    // Start background processors.
    zap::start_background_processor(
        repository.clone(),
        nostr_keys.as_ref(),
        invoice_paid_rx.clone(),
    );
    webhooks::start_background_processor(
        repository.clone(),
        http_client,
        invoice_paid_rx,
        args.webhook_delivery_ttl_days,
        webhook_config_cache,
    );

    // Get or create a shared webhook secret persisted in the database.
    // All instances share the same secret so webhooks verify correctly
    // regardless of which instance receives them.
    let default_secret = hex::encode(rand::random::<[u8; 32]>());
    let webhook_secret = repository
        .get_or_create_setting("webhook_secret", &default_secret)
        .await?;

    if let Some(webhook_domain) = &args.webhook_domain {
        let webhook_url = format!("{}://{}/webhook", args.scheme, webhook_domain);
        register_webhook(spark_client.clone(), webhook_url, webhook_secret.clone());
    }

    let blink_client =
        blink_client::Client::new(blink_client::ClientConfig::new(blink_graphql_endpoint));
    let providers = Arc::new(ProviderRegistry::new_with_blink_webhook_url(
        spark_client.clone(),
        blink_client,
        blink_webhook_url,
    ));

    let state = State {
        db: repository,
        spark_client,
        providers,
        internal_auth,
        scheme: args.scheme,
        min_sendable: args.min_sendable,
        max_sendable: args.max_sendable,
        include_spark_address: {
            #[cfg(feature = "dev")]
            {
                args.dev_dont_use_lnurl_include_spark_address
            }
            #[cfg(not(feature = "dev"))]
            {
                false
            }
        },
        domains,
        nostr_keys,
        ca_cert,
        crl_url: args.crl_url,
        crl,
        invoice_paid_trigger,
        webhook_secret,
    };

    // Mounted below as POST /internal/blink/accounts for Blink Core.
    let internal_router = Router::new()
        .route(
            "/blink/accounts",
            post(LnurlServer::<DB>::create_internal_blink_account),
        )
        .route(
            "/domains/{domain}/identifiers/{identifier}",
            get(LnurlServer::<DB>::get_internal_identifier),
        )
        .route(
            "/identifiers/transfer-to-spark",
            post(LnurlServer::<DB>::transfer_identifier_to_spark),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            internal_auth::internal_auth::<DB>,
        ));

    let server_router = Router::new()
        .nest("/internal", internal_router)
        .route(
            "/lnurlpay/available/{identifier}",
            get(LnurlServer::<DB>::available),
        )
        .route("/lnurlpay/{pubkey}", post(LnurlServer::<DB>::register))
        .route("/lnurlpay/{pubkey}", delete(LnurlServer::<DB>::unregister))
        .route(
            "/lnurlpay/{pubkey}/transfer",
            post(LnurlServer::<DB>::transfer),
        )
        .route(
            "/lnurlpay/{pubkey}/recover",
            post(LnurlServer::<DB>::recover),
        )
        .route(
            "/lnurlpay/{pubkey}/metadata",
            get(LnurlServer::<DB>::list_metadata),
        )
        .route(
            "/lnurlpay/{pubkey}/metadata/{payment_hash}/zap",
            post(LnurlServer::<DB>::publish_zap_receipt),
        )
        .route(
            "/lnurlpay/{pubkey}/invoice-paid",
            post(LnurlServer::<DB>::invoice_paid),
        )
        .route(
            "/lnurlpay/{pubkey}/invoices-paid",
            post(LnurlServer::<DB>::invoices_paid),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth::<DB>,
        ))
        .route(
            "/.well-known/lnurlp/{identifier}",
            get(LnurlServer::<DB>::handle_lnurl_pay),
        )
        .route(
            "/lnurlp/{identifier}",
            get(LnurlServer::<DB>::handle_lnurl_pay),
        )
        .route(
            "/lnurlp/{identifier}/invoice",
            get(LnurlServer::<DB>::handle_invoice),
        )
        .route("/verify/{payment_hash}", get(LnurlServer::<DB>::verify))
        .route("/webhook", post(LnurlServer::<DB>::webhook))
        .route("/webhook/blink", post(LnurlServer::<DB>::blink_webhook))
        .route("/health", get(|| async { StatusCode::OK }))
        .layer(Extension(state))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(Any)
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS]),
        )
        .layer(DefaultBodyLimit::max(1_000_000));

    let listener = tokio::net::TcpListener::bind(args.address).await?;
    let server = axum::serve(listener, server_router.into_make_service());

    let graceful = server.with_graceful_shutdown(async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to create Ctrl+C shutdown signal");
    });

    // Await the server to receive the shutdown signal
    if let Err(e) = graceful.await {
        error!("shutdown error: {e}");
    }

    info!("lnurl server stopped");
    Ok(())
}

async fn load_internal_auth_state(args: &Args) -> Option<Arc<internal_auth::InternalAuthState>> {
    let (Some(issuer), Some(audience)) = (
        args.internal_jwt_issuer.clone(),
        args.internal_jwt_audience.clone(),
    ) else {
        debug!("internal auth issuer/audience not fully configured; /internal fails closed");
        return None;
    };

    let jwks_json = if let Some(path) = &args.internal_jwks_path {
        match std::fs::read_to_string(path) {
            Ok(jwks) => Some(jwks),
            Err(e) => {
                error!("failed to read internal JWKS from {path}: {e}");
                None
            }
        }
    } else if let Some(url) = &args.internal_jwks_url {
        match reqwest::Client::new().get(url).send().await {
            Ok(response) => match response.text().await {
                Ok(jwks) => Some(jwks),
                Err(e) => {
                    error!("failed to read internal JWKS response body from {url}: {e}");
                    None
                }
            },
            Err(e) => {
                error!("failed to fetch internal JWKS from {url}: {e}");
                None
            }
        }
    } else {
        debug!("internal auth JWKS source not configured; /internal fails closed");
        None
    }?;

    match internal_auth::InternalAuthState::from_jwks_json(&jwks_json, issuer, audience) {
        Ok(state) => Some(Arc::new(state)),
        Err(e) => {
            error!("failed to parse internal JWKS; /internal fails closed: {e}");
            None
        }
    }
}

fn register_webhook(spark_client: spark_client::Client, webhook_url: String, secret: String) {
    tokio::spawn(async move {
        let mut delay = std::time::Duration::from_secs(1);
        let max_delay = std::time::Duration::from_mins(1);
        loop {
            info!("registering webhook with SSP at {}", webhook_url);
            match spark_client
                .register_wallet_webhook(spark_client::WebhookRegistrationRequest {
                    webhook_url: webhook_url.clone(),
                    secret: secret.clone(),
                })
                .await
            {
                Ok(_) => {
                    info!("webhook registered successfully");
                    break;
                }
                Err(e) => {
                    error!(
                        "failed to register webhook with SSP: {:?}, retrying in {:?}",
                        e, delay
                    );
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2).min(max_delay);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_blink_graphql_endpoint_override_is_optional() {
        let args = Args::parse_from(["lnurl-server"]);

        assert_eq!(args.blink_graphql_endpoint, None);
    }

    #[test]
    fn resolve_runtime_config_success_cases() {
        struct Case {
            deployment_env: &'static str,
            configured_spark_network: Option<spark_client::Network>,
            configured_blink_graphql_endpoint: Option<&'static str>,
            expected_spark_network: spark_client::Network,
            expected_blink_network: &'static str,
            expected_blink_graphql_endpoint: &'static str,
        }

        for case in [
            Case {
                deployment_env: "production",
                configured_spark_network: None,
                configured_blink_graphql_endpoint: None,
                expected_spark_network: spark_client::Network::Mainnet,
                expected_blink_network: "mainnet",
                expected_blink_graphql_endpoint: blink_client::PRODUCTION_GRAPHQL_ENDPOINT,
            },
            Case {
                deployment_env: "staging",
                configured_spark_network: None,
                configured_blink_graphql_endpoint: None,
                expected_spark_network: spark_client::Network::Regtest,
                expected_blink_network: "signet",
                expected_blink_graphql_endpoint: blink_client::STAGING_GRAPHQL_ENDPOINT,
            },
            Case {
                deployment_env: "local",
                configured_spark_network: None,
                configured_blink_graphql_endpoint: Some("http://127.0.0.1:4455/graphql"),
                expected_spark_network: spark_client::Network::Regtest,
                expected_blink_network: "regtest",
                expected_blink_graphql_endpoint: "http://127.0.0.1:4455/graphql",
            },
            Case {
                deployment_env: "staging",
                configured_spark_network: Some(spark_client::Network::Mainnet),
                configured_blink_graphql_endpoint: Some("http://127.0.0.1:4455/graphql"),
                expected_spark_network: spark_client::Network::Mainnet,
                expected_blink_network: "signet",
                expected_blink_graphql_endpoint: "http://127.0.0.1:4455/graphql",
            },
            Case {
                deployment_env: "production",
                configured_spark_network: None,
                configured_blink_graphql_endpoint: Some("   "),
                expected_spark_network: spark_client::Network::Mainnet,
                expected_blink_network: "mainnet",
                expected_blink_graphql_endpoint: blink_client::PRODUCTION_GRAPHQL_ENDPOINT,
            },
            Case {
                deployment_env: "staging",
                configured_spark_network: None,
                configured_blink_graphql_endpoint: Some("\t"),
                expected_spark_network: spark_client::Network::Regtest,
                expected_blink_network: "signet",
                expected_blink_graphql_endpoint: blink_client::STAGING_GRAPHQL_ENDPOINT,
            },
        ] {
            let (spark_network, blink_network, blink_graphql_endpoint) = resolve_runtime_config(
                Some(case.deployment_env),
                case.configured_spark_network,
                case.configured_blink_graphql_endpoint,
            )
            .expect("success case should resolve");

            assert_eq!(spark_network, case.expected_spark_network);
            assert_eq!(blink_network, case.expected_blink_network);
            assert_eq!(blink_graphql_endpoint, case.expected_blink_graphql_endpoint);
        }
    }

    #[test]
    fn resolve_runtime_config_error_cases() {
        for (deployment_env, configured_blink_graphql_endpoint, expected_error) in [
            (None, None, "DEPLOYMENT_ENV is required"),
            (Some("qa"), None, "unsupported DEPLOYMENT_ENV 'qa'"),
            (
                Some("local"),
                None,
                "LNURL_BLINK_GRAPHQL_ENDPOINT is required when DEPLOYMENT_ENV=local",
            ),
            (
                Some("local"),
                Some(""),
                "LNURL_BLINK_GRAPHQL_ENDPOINT is required when DEPLOYMENT_ENV=local",
            ),
            (
                Some("local"),
                Some("   "),
                "LNURL_BLINK_GRAPHQL_ENDPOINT is required when DEPLOYMENT_ENV=local",
            ),
            (
                Some("local"),
                Some("\t"),
                "LNURL_BLINK_GRAPHQL_ENDPOINT is required when DEPLOYMENT_ENV=local",
            ),
        ] {
            let err =
                resolve_runtime_config(deployment_env, None, configured_blink_graphql_endpoint)
                    .expect_err("error case must fail");

            assert!(err.to_string().contains(expected_error));
        }
    }

    #[test]
    fn startup_requires_webhook_domain_for_blink_webhook_url() {
        let args = Args::parse_from(["lnurl-server", "--scheme", "https"]);

        let err = build_blink_webhook_url(&args)
            .expect_err("Blink webhook URL construction must require LNURL_WEBHOOK_DOMAIN");

        assert!(
            err.to_string().contains("LNURL_WEBHOOK_DOMAIN"),
            "error should name the missing LNURL_WEBHOOK_DOMAIN: {err}"
        );
    }

    #[test]
    fn blink_webhook_url_uses_scheme_domain_and_fixed_path() {
        let args = Args::parse_from([
            "lnurl-server",
            "--scheme",
            "https",
            "--webhook-domain",
            "lnurl.example",
        ]);

        let url =
            build_blink_webhook_url(&args).expect("configured webhook domain should build URL");

        assert_eq!(url, "https://lnurl.example/webhook/blink");
    }
}
