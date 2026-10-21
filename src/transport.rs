mod http;
mod setup;
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
    fn authority(&mut self, _domain: &str) -> Result<Value> {
        Err(error("authority_unavailable"))
    }
}

pub trait WriteTransport: ReadTransport {
    fn post(&mut self, path: &str, body: &Value) -> Result<Value>;
    fn put(&mut self, path: &str, body: &Value) -> Result<Value>;
}

/// Additional DNS-record methods; existing migration transports need no new authority.
pub trait RecordWriteTransport: WriteTransport {
    fn patch(&mut self, path: &str, body: &Value) -> Result<Value>;
    fn delete(&mut self, path: &str) -> Result<Value>;
}

pub struct HttpTransport {
    client: Client,
    authorization: Option<HeaderValue>,
    pub(crate) provider: Provider,
    deadline: Instant,
    requests_left: usize,
    bytes_left: usize,
}
impl ReadTransport for HttpTransport {
    fn authority(&mut self, domain: &str) -> Result<Value> {
        if !matches!(self.provider, Provider::PublicDns) || self.authorization.is_some() {
            return Err(error("authority_requires_no_credential"));
        }
        if self.requests_left < 28
            || self.deadline.saturating_duration_since(Instant::now()) < Duration::from_secs(24)
        {
            return Err(error("authority_budget"));
        }
        self.requests_left -= 28;
        crate::authority::observe(domain)
    }
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

#[cfg(test)]
#[path = "transport_record_tests.rs"]
mod record_tests;
