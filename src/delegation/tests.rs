use super::referral::referral;
use hickory_proto::{
    op::OpCode,
    rr::{
        Record,
        rdata::{A, NS},
    },
};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType},
};
use std::net::Ipv4Addr;
fn fixture() -> (Message, Message) {
    let mut q = Message::query();
    q.queries.push(Query::query(
        Name::from_ascii("example.org.").unwrap(),
        RecordType::NS,
    ));
    let mut r = Message::response(q.metadata.id, OpCode::Query);
    r.queries = q.queries.clone();
    r.authorities.push(Record::from_rdata(
        Name::from_ascii("example.org.").unwrap(),
        3600,
        RData::NS(NS(Name::from_ascii("ns1.example.net.").unwrap())),
    ));
    r.additionals.push(Record::from_rdata(
        Name::from_ascii("ns1.example.net.").unwrap(),
        3600,
        RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
    ));
    (q, r)
}
#[test]
fn referral_accepts_matching_parent_question_and_public_glue() {
    let (q, r) = fixture();
    let (owner, names, ips) = referral(&r, &q, "example.org").unwrap();
    assert_eq!(owner, "example.org");
    assert_eq!(names, vec!["ns1.example.net"]);
    assert_eq!(ips, vec![Ipv4Addr::new(8, 8, 8, 8)]);
}
#[test]
fn wrong_id_truncation_child_authority_and_unrelated_zone_are_rejected() {
    let (q, r) = fixture();
    let mut bad = r.clone();
    bad.metadata.id = q.metadata.id.wrapping_add(1);
    assert!(referral(&bad, &q, "example.org").is_err());
    let mut bad = r.clone();
    bad.metadata.truncation = true;
    assert!(referral(&bad, &q, "example.org").is_err());
    let mut bad = r.clone();
    bad.metadata.authoritative = true;
    assert!(referral(&bad, &q, "example.org").is_err());
    assert!(referral(&r, &q, "another.org").is_err());
    let mut bad = r;
    bad.queries.clear();
    assert!(referral(&bad, &q, "example.org").is_err());
}
#[test]
fn internal_reserved_and_unrelated_glue_are_not_network_targets() {
    let (q, mut r) = fixture();
    r.additionals.clear();
    for ip in [
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(198, 18, 0, 1),
    ] {
        r.additionals.push(Record::from_rdata(
            Name::from_ascii("ns1.example.net.").unwrap(),
            3600,
            RData::A(A(ip)),
        ));
    }
    r.additionals.push(Record::from_rdata(
        Name::from_ascii("unrelated.example.net.").unwrap(),
        3600,
        RData::A(A(Ipv4Addr::new(8, 8, 4, 4))),
    ));
    assert!(referral(&r, &q, "example.org").unwrap().2.is_empty());
}
