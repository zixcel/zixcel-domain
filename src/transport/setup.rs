use super::*;
impl HttpTransport {
    /// Narrow a caller's deadline; never expands the existing transport budget.
    pub fn limit_time(&mut self, limit: Duration) -> Result<()> {
        if limit < Duration::from_millis(50) || limit > Duration::from_secs(40) {
            return Err(error("invalid_time_budget"));
        }
        self.deadline = self.deadline.min(Instant::now() + limit);
        Ok(())
    }

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

    pub(super) fn new(provider: Provider, authorization: Option<HeaderValue>) -> Result<Self> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caller_deadline_only_narrows_existing_budget() {
        let mut transport = HttpTransport::public_dns().unwrap();
        let initial = transport.deadline;
        transport.limit_time(Duration::from_secs(1)).unwrap();
        let narrowed = transport.deadline;
        assert!(narrowed < initial);
        transport.limit_time(Duration::from_secs(5)).unwrap();
        assert_eq!(transport.deadline, narrowed);
        assert!(transport.limit_time(Duration::ZERO).is_err());
        assert!(transport.limit_time(Duration::from_secs(41)).is_err());
    }
}
