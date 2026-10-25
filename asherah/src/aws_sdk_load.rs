//! Shared [`aws_config::defaults`] loader for KMS, DynamoDB, Secrets Manager.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
static DNS_IN_FLIGHT: AtomicU64 = AtomicU64::new(0);

// host -> state of the most recent lookup in this process; the connector tries IPs in answer order.
static LAST_DNS: Mutex<Option<HashMap<String, (u64, Instant, Option<String>)>>> = Mutex::new(None);

fn set_last_dns(host: &str, seq: u64, started: Instant, answer: Option<String>) {
    if let Ok(mut m) = LAST_DNS.lock() {
        let m = m.get_or_insert_with(HashMap::new);
        // Never let an older lookup overwrite a newer one.
        if m.get(host).map_or(true, |(s, _, _)| *s <= seq) {
            m.insert(host.to_string(), (seq, started, answer));
        }
    }
}

/// State of the most recent DNS lookup for `host`, for failure logs.
pub(crate) fn last_kms_dns(host: &str) -> String {
    let entry = LAST_DNS
        .lock()
        .ok()
        .and_then(|m| m.as_ref().and_then(|m| m.get(host).cloned()));
    let in_flight = DNS_IN_FLIGHT.load(Ordering::Relaxed);
    match entry {
        None => format!("none pid={} dns_in_flight={in_flight}", std::process::id()),
        Some((seq, started, None)) => format!(
            "#{seq} STILL_PENDING {}ms pid={} dns_in_flight={in_flight}",
            started.elapsed().as_millis(),
            std::process::id()
        ),
        Some((seq, _, Some(answer))) => format!(
            "#{seq} {answer} pid={} dns_in_flight={in_flight}",
            std::process::id()
        ),
    }
}

const DNS_WATCHDOG: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
];

#[derive(Debug, Clone)]
struct LoggingResolver;

impl ResolveDns for LoggingResolver {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        DnsFuture::new(async move {
            let seq = CONNECT_SEQ.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let started = Instant::now();
            let in_flight = DNS_IN_FLIGHT.fetch_add(1, Ordering::Relaxed) + 1;
            set_last_dns(name, seq, started, None);
            log::warn!("KMS dns #{seq}: START {name} pid={pid} dns_in_flight={in_flight}");

            // The lookup runs in its own task so it keeps going, and keeps
            // logging, after the SDK's connect timeout drops this future.
            let done = Arc::new(AtomicBool::new(false));
            let host = name.to_string();
            let (tx, rx) = tokio::sync::oneshot::channel();
            {
                let done = Arc::clone(&done);
                tokio::spawn(async move {
                    let result = tokio::net::lookup_host((host.as_str(), 443)).await;
                    done.store(true, Ordering::Relaxed);
                    DNS_IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
                    let ms = started.elapsed().as_millis();
                    let caller_gone = tx.is_closed();
                    let note = if caller_gone { " (SDK already gave up)" } else { "" };
                    let result = match result {
                        Ok(addrs) => {
                            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                            log::warn!(
                                "KMS dns #{seq}: DONE {host} -> {ips:?} dns_ms={ms} pid={pid}{note}"
                            );
                            let first = ips
                                .first()
                                .map(|ip| ip.to_string())
                                .unwrap_or_else(|| "none".into());
                            set_last_dns(
                                &host,
                                seq,
                                started,
                                Some(format!("first_tried={first} all={ips:?} dns_ms={ms}")),
                            );
                            Ok(ips)
                        }
                        Err(e) => {
                            log::warn!(
                                "KMS dns #{seq}: FAILED {host} after {ms}ms pid={pid}{note}: {e}"
                            );
                            set_last_dns(
                                &host,
                                seq,
                                started,
                                Some(format!("lookup_error after {ms}ms: {e}")),
                            );
                            Err(e)
                        }
                    };
                    drop(tx.send(result));
                });
            }
            {
                let done = Arc::clone(&done);
                let host = name.to_string();
                tokio::spawn(async move {
                    for after in DNS_WATCHDOG {
                        tokio::time::sleep_until((started + after).into()).await;
                        if done.load(Ordering::Relaxed) {
                            return;
                        }
                        log::warn!(
                            "KMS dns #{seq}: STILL PENDING {host} after {}ms pid={pid} dns_in_flight={}",
                            after.as_millis(),
                            DNS_IN_FLIGHT.load(Ordering::Relaxed)
                        );
                    }
                });
            }

            match rx.await {
                Ok(Ok(ips)) => Ok(ips),
                Ok(Err(e)) => Err(ResolveDnsError::new(e)),
                Err(_) => Err(ResolveDnsError::new(std::io::Error::other(
                    "DNS lookup task was dropped",
                ))),
            }
        })
    }
}
