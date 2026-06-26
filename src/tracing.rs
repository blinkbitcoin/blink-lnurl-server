use std::env;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use tracing::{Level, Span, field::display};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

const DEFAULT_SERVICE_NAME: &str = "blink-lnurl-server-dev";

#[macro_export]
macro_rules! traced_route {
    ($handler:expr, $name:literal, $route:literal) => {
        $handler.layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<_>| {
                    let path = request.uri().path();
                    let query = request.uri().query();
                    let span = ::tracing::info_span!(
                        $name,
                        "http.method" = %request.method(),
                        "http.route" = $route,
                        "url.path" = %path,
                        "url.query" = %query.unwrap_or(""),
                        "code.function.params.identifier" = ::tracing::field::Empty,
                        "code.function.params.pubkey" = ::tracing::field::Empty,
                        "code.function.params.payment_hash" = ::tracing::field::Empty,
                        "code.function.params.domain" = ::tracing::field::Empty,
                        "code.function.params.blink_account_id" = ::tracing::field::Empty,
                        "code.function.params.to_pubkey" = ::tracing::field::Empty,
                        "code.function.params.amount" = ::tracing::field::Empty,
                        "code.function.params.expiry" = ::tracing::field::Empty,
                        "code.function.params.offset" = ::tracing::field::Empty,
                        "code.function.params.limit" = ::tracing::field::Empty,
                        "code.function.params.updated_after" = ::tracing::field::Empty,
                        "http.status_code" = ::tracing::field::Empty,
                        "error" = ::tracing::field::Empty,
                        "error.level" = ::tracing::field::Empty,
                        "error.message" = ::tracing::field::Empty,
                    );
                    $crate::tracing::record_http_params(&span, $route, path, query);
                    span
                })
                .on_response(|response: &axum::http::Response<_>, _, span: &::tracing::Span| {
                    $crate::tracing::record_http_status(span, response.status());
                }),
        )
    };
}

pub fn init(log_level: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_target(false)
        .with_writer(std::io::stdout);

    let subscriber = tracing_subscriber::registry().with(filter).with(fmt_layer);

    let otlp_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
    let otlp_exporter = env::var("OTEL_TRACES_EXPORTER").ok();

    if otlp_enabled(otlp_exporter.as_deref(), otlp_endpoint.as_deref()) {
        let service_name = service_name();
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(otlp_endpoint.expect("checked above"))
            .build()?;
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                opentelemetry_sdk::Resource::builder_empty()
                    .with_service_name(service_name.clone())
                    .build(),
            )
            .build();
        opentelemetry::global::set_tracer_provider(provider.clone());
        let telemetry = tracing_opentelemetry::layer().with_tracer(provider.tracer(service_name));

        subscriber.with(telemetry).try_init()?;
    } else {
        subscriber.try_init()?;
    }

    Ok(())
}

fn otlp_enabled(exporter: Option<&str>, endpoint: Option<&str>) -> bool {
    exporter == Some("otlp") && endpoint.is_some_and(|value| !value.trim().is_empty())
}

fn service_name() -> String {
    env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| DEFAULT_SERVICE_NAME.to_string())
}

pub fn record_http_status(span: &Span, status: axum::http::StatusCode) {
    span.record("http.status_code", display(status.as_u16()));
    if status.is_client_error() || status.is_server_error() {
        span.record("error", display("true"));
        span.record(
            "error.level",
            display(if status.is_server_error() {
                Level::ERROR
            } else {
                Level::WARN
            }),
        );
        span.record("error.message", display(status));
    }
}

pub fn record_http_params(span: &Span, route: &str, path: &str, query: Option<&str>) {
    for name in [
        "identifier",
        "pubkey",
        "payment_hash",
        "domain",
        "blink_account_id",
    ] {
        record_param(span, name, path_param(route, path, name));
    }
    if route == "/lnurlpay/{pubkey}/transfer" {
        record_param(span, "to_pubkey", path_param(route, path, "pubkey"));
    }
    for name in ["amount", "expiry", "offset", "limit", "updated_after"] {
        record_param(span, name, query_param(query, name));
    }
}

fn record_param(span: &Span, name: &str, value: Option<String>) {
    if let Some(value) = value {
        span.record(
            format!("code.function.params.{name}").as_str(),
            display(value),
        );
    }
}

pub fn path_param(route: &str, path: &str, name: &str) -> Option<String> {
    let pattern = format!("{{{name}}}");
    route
        .trim_matches('/')
        .split('/')
        .zip(path.trim_matches('/').split('/'))
        .find_map(|(route_part, path_part)| (route_part == pattern).then(|| path_part.to_string()))
}

pub fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otlp_requires_exporter_and_endpoint() {
        assert!(otlp_enabled(Some("otlp"), Some("http://localhost:4317")));
        assert!(!otlp_enabled(Some("none"), Some("http://localhost:4317")));
        assert!(!otlp_enabled(Some("otlp"), Some("")));
        assert!(!otlp_enabled(Some("otlp"), None));
    }

    #[test]
    fn extracts_safe_http_params() {
        assert_eq!(
            super::path_param(
                "/lnurlp/{identifier}/invoice",
                "/lnurlp/alice/invoice",
                "identifier"
            ),
            Some("alice".to_string())
        );
        assert_eq!(
            super::path_param("/verify/{payment_hash}", "/verify/abc", "payment_hash"),
            Some("abc".to_string())
        );
        assert_eq!(super::path_param("/health", "/health", "identifier"), None);
        assert_eq!(
            super::query_param(Some("amount=1000&expiry=300"), "amount"),
            Some("1000".to_string())
        );
        assert_eq!(
            super::query_param(Some("amount=1000&expiry=300"), "expiry"),
            Some("300".to_string())
        );
        assert_eq!(
            super::query_param(
                Some("offset=10&limit=50&updated_after=123"),
                "updated_after"
            ),
            Some("123".to_string())
        );
        assert_eq!(super::query_param(Some("amount=1000"), "expiry"), None);
    }
}
