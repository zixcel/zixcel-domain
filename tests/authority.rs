use hickory_proto::{
    op::{Message, OpCode, Query},
    rr::{Name, RData, Record, RecordType, rdata::NS},
};
use zixcel_domain::authority::decode;
fn query() -> Message {
    let mut q = Message::query();
    q.queries.push(Query::query(
        Name::from_ascii("example.org.").unwrap(),
        RecordType::NS,
    ));
    q
}
#[test]
fn exact_authoritative_rrset_is_required() {
    let q = query();
    let mut r = Message::response(q.metadata.id, OpCode::Query);
    r.queries = q.queries.clone();
    r.metadata.authoritative = true;
    r.answers.push(Record::from_rdata(
        Name::from_ascii("example.org.").unwrap(),
        300,
        RData::NS(NS(Name::from_ascii("ns1.example.net.").unwrap())),
    ));
    assert_eq!(decode(&r, &q, RecordType::NS).unwrap().len(), 1);
    assert!(decode(&r, &q, RecordType::DS).is_err());
    let mut bad = r.clone();
    bad.metadata.authoritative = false;
    assert!(decode(&bad, &q, RecordType::NS).is_err());
    let mut bad = r.clone();
    bad.metadata.truncation = true;
    assert!(decode(&bad, &q, RecordType::NS).is_err());
    let mut bad = r;
    bad.metadata.id = q.metadata.id.wrapping_add(1);
    assert!(decode(&bad, &q, RecordType::NS).is_err());
}
#[test]
fn empty_packets_or_wrong_owners_are_not_absence_evidence() {
    let q = query();
    let mut r = Message::response(q.metadata.id, OpCode::Query);
    r.queries = q.queries.clone();
    r.metadata.authoritative = true;
    assert!(decode(&r, &q, RecordType::NS).is_err());
    r.answers.push(Record::from_rdata(
        Name::from_ascii("other.org.").unwrap(),
        300,
        RData::NS(NS(Name::from_ascii("ns1.example.net.").unwrap())),
    ));
    assert!(decode(&r, &q, RecordType::NS).is_err());
    assert!(decode(&r, &Message::query(), RecordType::NS).is_err());
}
