use std::{collections::HashSet, sync::Arc};
use tokio::sync::{RwLock, watch};

use crate::country::CountryResolver;
use crate::providers::ProviderRegistry;
use crate::rate_limit::PerIpRateLimiter;

pub struct State<DB> {
    pub db: DB,
    pub spark_client: spark_client::Client,
    pub providers: Arc<ProviderRegistry>,
    pub internal_auth: Option<Arc<crate::internal_auth::InternalAuthState>>,
    pub country_resolver: Arc<CountryResolver>,
    /// Shared per-IP budget for the mode route and for the paid country
    /// lookups the signed-request handlers make.
    pub ip_rate_limiter: Arc<PerIpRateLimiter>,
    pub scheme: String,
    pub callback_domain: Option<String>,
    pub min_sendable: u64,
    pub max_sendable: u64,
    pub include_spark_address: bool,
    pub domains: Arc<RwLock<HashSet<String>>>,
    pub nostr_keys: Option<nostr::Keys>,
    pub ca_cert: Option<Vec<u8>>,
    pub crl_url: Option<String>,
    pub crl: HashSet<String>,
    pub invoice_paid_trigger: watch::Sender<()>,
    pub webhook_secret: String,
}

impl<DB> Clone for State<DB>
where
    DB: Clone,
{
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            spark_client: self.spark_client.clone(),
            providers: Arc::clone(&self.providers),
            internal_auth: self.internal_auth.as_ref().map(Arc::clone),
            country_resolver: Arc::clone(&self.country_resolver),
            ip_rate_limiter: Arc::clone(&self.ip_rate_limiter),
            scheme: self.scheme.clone(),
            callback_domain: self.callback_domain.clone(),
            min_sendable: self.min_sendable,
            max_sendable: self.max_sendable,
            include_spark_address: self.include_spark_address,
            domains: Arc::clone(&self.domains),
            nostr_keys: self.nostr_keys.clone(),
            ca_cert: self.ca_cert.clone(),
            crl_url: self.crl_url.clone(),
            crl: self.crl.clone(),
            invoice_paid_trigger: self.invoice_paid_trigger.clone(),
            webhook_secret: self.webhook_secret.clone(),
        }
    }
}
