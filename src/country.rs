use std::net::IpAddr;
use std::time::Duration;

use axum::http::HeaderMap;
use serde_json::Value;
use tracing::{trace, warn};

/// The single trusted client-IP header; the edge must strip or overwrite any
/// client-supplied value.
const CLIENT_IP_HEADER: &str = "x-real-ip";

pub const DEFAULT_PROXYCHECK_URL: &str = "https://proxycheck.io/v2";

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

pub fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(CLIENT_IP_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
}

/// proxycheck.io client. Consumes `isocode` only — proxy/risk/ASN are never read.
#[derive(Clone)]
pub struct CountryResolver {
    client: reqwest::Client,
    base_url: Option<String>,
    api_key: Option<String>,
}

impl CountryResolver {
    pub fn disabled() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: None,
            api_key: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.base_url.is_some()
    }

    pub fn new(base_url: &str, api_key: Option<String>) -> Result<Self, anyhow::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(RESOLVE_TIMEOUT)
                .build()?,
            base_url: Some(base_url.trim_end_matches('/').to_string()),
            api_key,
        })
    }

    /// Resolve an ISO 3166-1 alpha-2 country for `ip`. Returns `None` on any
    /// failure — callers fail open. The IP is discarded here and never logged.
    pub async fn resolve(&self, ip: Option<IpAddr>) -> Option<String> {
        let base_url = self.base_url.as_deref()?;
        let ip = ip?;

        // Without asn=1 the vendor omits every geo field, isocode included.
        let mut request = self
            .client
            .get(format!("{base_url}/{ip}"))
            .query(&[("asn", "1")]);
        if let Some(api_key) = self.api_key.as_deref() {
            request = request.query(&[("key", api_key)]);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(e) => {
                warn!("country resolution request failed: {}", e.without_url());
                return None;
            }
        };
        if !response.status().is_success() {
            warn!("country resolution returned status {}", response.status());
            return None;
        }
        let body: Value = match response.json().await {
            Ok(body) => body,
            Err(e) => {
                warn!("country resolution body was not JSON: {}", e.without_url());
                return None;
            }
        };

        // The vendor rejects inside an HTTP 200 (bad key, spent quota);
        // `warning` still carries a usable result.
        if let Some(status) = body.get("status").and_then(Value::as_str)
            && !status.eq_ignore_ascii_case("ok")
        {
            let message = body.get("message").and_then(Value::as_str).unwrap_or("");
            warn!("country resolution answered with status '{status}': {message}");
            if !status.eq_ignore_ascii_case("warning") {
                return None;
            }
        }

        let country = entry_for_ip(&body, ip)
            .and_then(|entry| entry.get("isocode"))
            .and_then(Value::as_str)
            .and_then(normalize_iso_code);
        if country.is_none() {
            trace!("country resolution returned no usable isocode");
        }
        country
    }
}

/// The vendor may key its entry in another textual form (IPv6 compression).
fn entry_for_ip(body: &Value, ip: IpAddr) -> Option<&Value> {
    body.as_object()?
        .iter()
        .find(|(key, _)| key.parse::<IpAddr>().is_ok_and(|parsed| parsed == ip))
        .map(|(_, entry)| entry)
}

fn normalize_iso_code(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() == 2 && value.chars().all(|c| c.is_ascii_alphabetic()))
        .then(|| value.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        headers
    }

    #[test]
    fn client_ip_reads_only_the_trusted_header() {
        assert_eq!(
            client_ip(&headers_with("x-real-ip", " 203.0.113.7 ")),
            Some("203.0.113.7".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            client_ip(&headers_with("x-forwarded-for", "203.0.113.7")),
            None
        );
        assert_eq!(client_ip(&headers_with("x-real-ip", "not-an-ip")), None);
        assert_eq!(client_ip(&HeaderMap::new()), None);
    }

    #[test]
    fn iso_codes_are_normalized_and_validated() {
        assert_eq!(normalize_iso_code(" sv "), Some("SV".to_string()));
        assert_eq!(normalize_iso_code("US"), Some("US".to_string()));
        for invalid in ["", "U", "USA", "1S", "s v"] {
            assert_eq!(normalize_iso_code(invalid), None, "{invalid}");
        }
    }

    #[tokio::test]
    async fn disabled_resolver_never_calls_out() {
        let resolver = CountryResolver::disabled();
        assert_eq!(
            resolver.resolve(Some("203.0.113.7".parse().unwrap())).await,
            None
        );
    }

    /// A proxycheck.io stand-in that answers every path with `body`. Like the
    /// real vendor it withholds geo fields unless the query carries `asn=1`.
    async fn start_vendor_mock(body: serde_json::Value) -> CountryResolver {
        let app = axum::Router::new().fallback(
            move |axum::extract::RawQuery(query): axum::extract::RawQuery| {
                let mut body = body.clone();
                async move {
                    let has_asn_flag = query
                        .as_deref()
                        .unwrap_or("")
                        .split('&')
                        .any(|pair| pair == "asn=1");
                    if !has_asn_flag && let Some(entries) = body.as_object_mut() {
                        for entry in entries.values_mut() {
                            if let Some(entry) = entry.as_object_mut() {
                                entry.remove("isocode");
                            }
                        }
                    }
                    axum::Json(body)
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock listener should bind");
        let addr = listener
            .local_addr()
            .expect("mock listener should have addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("mock vendor should serve");
        });
        CountryResolver::new(&format!("http://{addr}"), None).expect("resolver builds")
    }

    #[tokio::test]
    async fn a_rejecting_vendor_status_resolves_to_no_country() {
        for status in ["denied", "error"] {
            let resolver = start_vendor_mock(serde_json::json!({
                "status": status,
                "message": "API key has exceeded its query limit.",
                "203.0.113.7": { "isocode": "SV" },
            }))
            .await;

            assert_eq!(
                resolver.resolve(Some("203.0.113.7".parse().unwrap())).await,
                None,
                "a '{status}' answer must never be read as a country"
            );
        }

        // A warning is non-fatal: the vendor still answered the query.
        let resolver = start_vendor_mock(serde_json::json!({
            "status": "warning",
            "message": "One of the IPs you supplied was invalid.",
            "203.0.113.7": { "isocode": "SV" },
        }))
        .await;
        assert_eq!(
            resolver.resolve(Some("203.0.113.7".parse().unwrap())).await,
            Some("SV".to_string())
        );
    }

    #[tokio::test]
    async fn entries_are_matched_as_addresses_not_strings() {
        let resolver = start_vendor_mock(serde_json::json!({
            "status": "ok",
            "2001:0db8:0000:0000:0000:0000:0000:0001": { "isocode": "sv" },
        }))
        .await;

        assert_eq!(
            resolver
                .resolve(Some("2001:db8::1".parse::<IpAddr>().unwrap()))
                .await,
            Some("SV".to_string()),
            "an IPv6 entry written in another textual form must still match"
        );
        assert_eq!(
            resolver
                .resolve(Some("2001:db8::2".parse::<IpAddr>().unwrap()))
                .await,
            None,
            "an entry for a different address must never be consumed"
        );
    }
}
