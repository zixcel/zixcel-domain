use crate::{
    Result, error,
    transport::{HttpTransport, Provider, RecordWriteTransport},
};
use serde_json::Value;

impl RecordWriteTransport for HttpTransport {
    fn patch(&mut self, path: &str, body: &Value) -> Result<Value> {
        if !matches!(self.provider, Provider::Cloudflare) {
            return Err(error("wrong_record_provider"));
        }
        self.request(reqwest::Method::PATCH, path, Some(body))
            .map_err(|error| error.with_context("cloudflare", "http_patch"))
    }
    fn delete(&mut self, path: &str) -> Result<Value> {
        if !matches!(self.provider, Provider::Cloudflare) {
            return Err(error("wrong_record_provider"));
        }
        self.request(reqwest::Method::DELETE, path, None)
            .map_err(|error| error.with_context("cloudflare", "http_delete"))
    }
}
