use super::*;
impl Api {
    fn write(&mut self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        self.writes += 1;
        self.method = method.into();
        if self.fail_write {
            return Err(Error::new("write_outcome_unknown"));
        }
        let id = if method == "POST" {
            assert_eq!(path, format!("/zones/{ZONE}/dns_records"));
            CREATED
        } else {
            assert_eq!(path, format!("/zones/{ZONE}/dns_records/{RECORD}"));
            RECORD
        };
        if !self.ignore_write {
            match method {
                "POST" => {
                    let mut v = body.unwrap().clone();
                    v["id"] = id.into();
                    self.records.push(v);
                }
                "PATCH" => {
                    let v = self.records.iter_mut().find(|v| v["id"] == id).unwrap();
                    if self.lose_metadata {
                        *v = json!({"id":id});
                    }
                    for (k, w) in body.unwrap().as_object().unwrap() {
                        v[k] = w.clone();
                    }
                    v["modified_on"] = "after".into();
                }
                "DELETE" => self.records.retain(|v| v["id"] != id),
                _ => panic!("unsupported write"),
            }
        }
        if self.collateral {
            self.records.iter_mut().find(|v| v["id"] != id).unwrap()["comment"] = "changed".into();
        }
        if self.lost_response {
            return Err(Error::new("write_outcome_unknown"));
        }
        Ok(json!({"success":true,"result":{"id":id}}))
    }
}
impl WriteTransport for Api {
    fn post(&mut self, p: &str, b: &Value) -> Result<Value> {
        self.write("POST", p, Some(b))
    }
    fn put(&mut self, _: &str, _: &Value) -> Result<Value> {
        panic!("PUT would discard metadata")
    }
}
impl RecordWriteTransport for Api {
    fn patch(&mut self, p: &str, b: &Value) -> Result<Value> {
        self.write("PATCH", p, Some(b))
    }
    fn delete(&mut self, p: &str) -> Result<Value> {
        self.write("DELETE", p, None)
    }
}
