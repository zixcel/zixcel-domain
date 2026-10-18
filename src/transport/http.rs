use super::*;
impl HttpTransport {
    pub(crate) fn request(
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
