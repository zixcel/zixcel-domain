use super::*;
impl ReadTransport for Api {
    fn get(&mut self, path: &str) -> Result<Value> {
        self.reads += 1;
        if self.fail_readback && self.writes > 0 {
            return Err(Error::new("transport_failed"));
        }
        if path == format!("/zones/{ZONE}") {
            if let Some(zone) = &self.zone_override {
                return Ok(json!({"success":true,"result":zone}));
            }
            return Ok(
                json!({"success":true,"result":{"id":ZONE,"name":"example.test","status":"active",
                "account":{"id":if self.wrong_scope { "wrong" } else { ACCOUNT }}}}),
            );
        }
        assert!(path.starts_with(&format!(
            "/zones/{ZONE}/dns_records?order=name&per_page=50&page="
        )));
        let page: usize = path.rsplit('=').next().unwrap().parse().unwrap();
        Ok(
            json!({"success":true,"result":self.records.iter().skip((page-1)*50).take(50).collect::<Vec<_>>(),
            "result_info":{"page":page,"total_count":self.records.len()}}),
        )
    }
}
