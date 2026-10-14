use serde_json::{Value, json};
use zixcel_domain::{Result, public_dns, transport::ReadTransport};
struct Fixture(Value);
impl ReadTransport for Fixture {
    fn get(&mut self, path: &str) -> Result<Value> {
        assert_eq!(path, "/dns-query?name=example.test&type=DS");
        Ok(self.0.clone())
    }
}
#[test]
fn nodata_is_a_query_result_and_never_complete_zone_inventory() {
    let mut transport = Fixture(
        json!({"Status":0,"TC":false,"AD":true,"Question":[{"name":"example.test.","type":43}]}),
    );
    let result = public_dns::query(&mut transport, "example.test", "DS").unwrap();
    assert!(result.answers.is_empty());
    assert!(!result.zone_inventory_complete);
    assert!(result.dnssec_validated);
}
#[test]
fn failed_and_wrong_question_responses_are_not_empty_success() {
    for response in [
        json!({"Status":2,"TC":false}),
        json!({"Status":0,"TC":false,"Question":[{"name":"other.test.","type":43}]}),
    ] {
        assert!(public_dns::query(&mut Fixture(response), "example.test", "DS").is_err());
    }
}
