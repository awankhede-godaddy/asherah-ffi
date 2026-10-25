//! Shared [`aws_config::defaults`] loader for KMS, DynamoDB, Secrets Manager.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use aws_config::meta::region::RegionProviderChain;
use aws_smithy_http_client::tls::{rustls_provider::CryptoMode, Provider};
use aws_smithy_runtime_api::client::dns::{DnsFuture, ResolveDns, ResolveDnsError};
use aws_smithy_runtime_api::client::http::SharedHttpClient;
use aws_types::SdkConfig;

const PROXY_ENV_VARS: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Load SDK config with optional named profile (`aws-config` credential chain).
pub(crate) async fn load_sdk_config(
    region_provider: RegionProviderChain,
    profile_name: Option<&str>,
) -> SdkConfig {
    let mut loader =
        aws_config::defaults(aws_config::BehaviorVersion::latest()).region(region_provider);
    if let Some(p) = profile_name {
        loader = loader.profile_name(p);
    }
    loader.load().await
}

/// HTTPS client for KMS that logs DNS resolution results.
///
/// Returns `None` (SDK default client) when a custom endpoint or proxy is in use.
pub(crate) fn kms_http_client(shared_config: &SdkConfig) -> Option<SharedHttpClient> {
    let custom_endpoint = shared_config.endpoint_url().is_some()
        || std::env::var_os("AWS_ENDPOINT_URL").is_some()
        || std::env::var_os("AWS_ENDPOINT_URL_KMS").is_some();
    let proxied = PROXY_ENV_VARS
        .iter()
        .any(|v| std::env::var_os(v).is_some());
    if custom_endpoint || proxied {
        return None;
    }
    Some(
        aws_smithy_http_client::Builder::new()
            .tls_provider(Provider::Rustls(CryptoMode::AwsLc))
            .build_with_resolver(LoggingResolver),
    )
}

static CONNECT_SEQ: AtomicU64 = AtomicU64::new(0);

// host -> most recent DNS answer in this process; the connector tries IPs in this order.
static LAST_DNS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

/// Most recent DNS answer for `host`, for failure logs.
pub(crate) fn last_kms_dns(host: &str) -> String {
    LAST_DNS
        .lock()
        .ok()
        .and_then(|m| m.as_ref().and_then(|m| m.get(host).cloned()))
        .unwrap_or_else(|| "none (no new connection in this process)".into())
}

#[derive(Debug, Clone)]
struct LoggingResolver;

impl ResolveDns for LoggingResolver {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        DnsFuture::new(async move {
            let started = Instant::now();
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name, 443))
                .await
                .map_err(ResolveDnsError::new)?
                .collect();
            let seq = CONNECT_SEQ.fetch_add(1, Ordering::Relaxed);
            let ips: Vec<_> = addrs.iter().map(|a| a.ip()).collect();
            log::warn!(
                "KMS connect #{seq}: DNS {name} -> {ips:?} dns_ms={}",
                started.elapsed().as_millis()
            );
            if let Ok(mut m) = LAST_DNS.lock() {
                m.get_or_insert_with(HashMap::new)
                    .insert(
                        name.to_string(),
                        format!(
                            "#{seq} first_tried={} all={ips:?}",
                            ips.first().map(|ip| ip.to_string()).unwrap_or_else(|| "none".into())
                        ),
                    );
            }
            Ok(ips)
        })
    }
}
