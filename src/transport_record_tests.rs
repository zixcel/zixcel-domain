use super::*;
use serde_json::json;
#[test]
fn new_record_methods_reject_other_providers_without_network_access() {
    for provider in [Provider::ValueDomain, Provider::PublicDns] {
        let mut http = HttpTransport::new(provider, None).unwrap();
        assert_eq!(
            http.patch("/zones/test/dns_records/test", &json!({}))
                .unwrap_err()
                .code,
            "wrong_record_provider"
        );
        assert_eq!(
            http.delete("/zones/test/dns_records/test")
                .unwrap_err()
                .code,
            "wrong_record_provider"
        );
    }
}
#[test]
fn record_methods_keep_existing_fixed_origin_path_validation() {
    let mut http = HttpTransport::new(Provider::Cloudflare, None).unwrap();
    for path in [
        "//other.test/path",
        "https://other.test/path",
        "/zones/../accounts",
        "/zones/test#other",
    ] {
        assert_eq!(
            http.patch(path, &json!({})).unwrap_err().code,
            "invalid_provider_path"
        );
        assert_eq!(http.delete(path).unwrap_err().code, "invalid_provider_path");
    }
}
