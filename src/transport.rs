use crate::{Result, error};
use reqwest::{
    blocking::Client,
    header::{AUTHORIZATION, HeaderValue},
};
use serde_json::Value;
use std::{
    io::Read,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub enum Provider {
    ValueDomain,
    Cloudflare,
    PublicDns,
}
impl Provider {
    fn name(self) -> &'static str {
        match self {
            Self::ValueDomain => "valuedomain-v2",
            Self::Cloudflare => "cloudflare",
            Self::PublicDns => "public-dns",
        }
    }
    fn base(self) -> &'static str {
        match self {
            Self::ValueDomain => "https://api-one.value-domain.com/v2",
            Self::Cloudflare => "https://api.cloudflare.com/client/v4",
            Self::PublicDns => "https://cloudflare-dns.com",
        }
    }
}

/// Test transports receive no credential. Live transport is a fixed-origin trusted host.
pub trait ReadTransport {
    fn get(&mut self, path: &str) -> Result<Value>;
    fn delegation(&mut self, _domain: &str) -> Result<Vec<String>> {
        Err(error("delegation_unavailable"))
    }
}

pub trait WriteTransport: ReadTransport {
    fn post(&mut self, path: &str, body: &Value) -> Result<Value>;
    fn put(&mut self, path: &str, body: &Value) -> Result<Value>;
}

pub struct HttpTransport {
    client: Client,
    authorization: Option<HeaderValue>,
    provider: Provider,
    deadline: Instant,
    requests_left: usize,
    bytes_left: usize,
}
impl HttpTransport {
    pub fn from_env(provider: Provider, variable: &str) -> Result<Self> {
        Self::from_env_inner(provider, variable)
            .map_err(|error| error.with_context(provider.name(), "credential_setup"))
    }
    fn from_env_inner(provider: Provider, variable: &str) -> Result<Self> {
        if matches!(provider, Provider::PublicDns) {
            return Err(error("public_dns_requires_no_credential"));
        }
        let token = std::env::var(variable).map_err(|_| error("credential_missing"))?;
        if token.is_empty() || token.len() > 8192 || token.bytes().any(|b| b.is_ascii_whitespace())
        {
            return Err(error("invalid_credential"));
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| error("invalid_credential"))?;
        authorization.set_sensitive(true);
        Self::new(provider, Some(authorization))
    }

    pub fn public_dns() -> Result<Self> {
        Self::new(Provider::PublicDns, None)
    }

    fn new(provider: Provider, authorization: Option<HeaderValue>) -> Result<Self> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .no_proxy()
            .build()
            .map_err(|_| error("transport_setup"))?;
        Ok(Self {
            client,
            authorization,
            provider,
            deadline: Instant::now() + Duration::from_secs(90),
            requests_left: 100,
            bytes_left: 8 * 1024 * 1024,
        })
    }
}
impl ReadTransport for HttpTransport {
    fn delegation(&mut self, domain: &str) -> Result<Vec<String>> {
        if !matches!(self.provider, Provider::PublicDns) || self.authorization.is_some() {
            return Err(error("delegation_requires_no_credential"));
        }
        if self.requests_left < 24
            || self.deadline.saturating_duration_since(Instant::now()) < Duration::from_secs(18)
        {
            return Err(error("request_budget"));
        }
        self.requests_left -= 24;
        crate::delegation::query(domain)
            .map_err(|error| error.with_context("public-dns", "read_parent_delegation"))
    }
    fn get(&mut self, path: &str) -> Result<Value> {
        self.request(reqwest::Method::GET, path, None)
            .map_err(|error| error.with_context(self.provider.name(), "http_get"))
    }
}
impl HttpTransport {
    fn request(
        &mut self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let writing = method != reqwest::Method::GET;
        if writing && matches!(self.provider, Provider::PublicDns) {
            return Err(error("public_dns_write_forbidden"));
        }
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains("..")
            || path.contains(['#', '\\', '\r', '\n'])
            || !path.is_ascii()
        {
            return Err(error("invalid_provider_path"));
        }
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| error("time_budget"))?;
        if self.requests_left == 0 || self.bytes_left == 0 {
            return Err(error("request_budget"));
        }
        self.requests_left -= 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.provider.base()))
            .timeout(remaining.min(Duration::from_secs(15)));
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body).map_err(|_| error("invalid_write_body"))?;
            if bytes.len() > 256 * 1024 {
                return Err(error("write_body_budget"));
            }
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes);
        }
        if let Some(authorization) = &self.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }
        if matches!(self.provider, Provider::PublicDns) {
            request = request.header(reqwest::header::ACCEPT, "application/dns-json");
        }
        let response = request.send().map_err(|_| {
            error(if writing {
                "write_outcome_unknown"
            } else {
                "transport_failed"
            })
        })?;
        if !response.status().is_success() {
            return Err(error(match response.status().as_u16() {
                401 => "unauthorized",
                403 => "forbidden",
                429 => "rate_limited",
                300..=399 => "redirect_refused",
                _ => "provider_failed",
            })
            .with_http_status(response.status().as_u16()));
        }
        let limit = self.bytes_left.min(1024 * 1024);
        let mut bytes = Vec::new();
        response
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error("response_failed"))?;
        if bytes.len() > limit {
            return Err(error("response_budget"));
        }
        self.bytes_left -= bytes.len();
        serde_json::from_slice(&bytes).map_err(|_| error("invalid_provider_json"))
    }
}

impl WriteTransport for HttpTransport {
    fn post(&mut self, path: &str, body: &Value) -> Result<Value> {
        self.request(reqwest::Method::POST, path, Some(body))
            .map_err(|error| error.with_context(self.provider.name(), "http_post"))
    }
    fn put(&mut self, path: &str, body: &Value) -> Result<Value> {
        self.request(reqwest::Method::PUT, path, Some(body))
            .map_err(|error| error.with_context(self.provider.name(), "http_put"))
    }
}
