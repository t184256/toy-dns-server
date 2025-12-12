use std::fs;
use std::net::Ipv4Addr;
use toy_dns_server::{
    DnsAnswer, DnsHeader, DnsPacket, DnsQuestion, OpCode, QClass, QType, RCode,
    RData, construct_reply, parse_dns_query,
};

#[test]
fn test_packet_parsing() {
    let data = fs::read("tests/example.query.bin")
        .expect("Failed to read example.query.bin");
    let packet = parse_dns_query(&data).expect("Failed to parse DNS query");

    let expected = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x751e,
            response: false,
            opcode: OpCode::QUERY,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: true,
            recursion_available: false,
            _reserved: false,
            authenticated_data: false,
            checking_disabled: false,
            rcode: RCode::NoError,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 1,
        },
        questions: vec![DnsQuestion {
            qname: "example.com".to_string(),
            qtype: QType::A,
            qclass: QClass::IN,
        }],
        answers: vec![],
        unparsed: vec![0, 0, 41, 5, 192, 0, 0, 0, 0, 0, 0],
    };

    assert_eq!(packet, expected);
}

#[test]
fn test_packet_serialization_roundtrip() {
    let data = fs::read("tests/example.query.bin")
        .expect("Failed to read example.query.bin");

    let packet = parse_dns_query(&data).expect("Failed to parse DNS query");
    let serialized = packet.serialize();

    assert_eq!(serialized.as_slice(), data);
}

#[test]
fn test_reply_to_example() {
    let data = fs::read("tests/example.query.bin")
        .expect("Failed to read example.query.bin");
    let query = parse_dns_query(&data).expect("Failed to parse DNS query");
    let reply = construct_reply(&query).expect("Should construct a reply");

    let expected = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x751e,
            response: true,
            opcode: OpCode::QUERY,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: true,
            recursion_available: false,
            _reserved: false,
            authenticated_data: false,
            checking_disabled: false,
            rcode: RCode::NoError,
            qd_count: 1,
            an_count: 1,
            ns_count: 0,
            ar_count: 0,
        },
        questions: vec![DnsQuestion {
            qname: "example.com".to_string(),
            qtype: QType::A,
            qclass: QClass::IN,
        }],
        answers: vec![DnsAnswer {
            name: "example.com".to_string(),
            rclass: QClass::IN,
            rtype: QType::A,
            ttl: 5,
            rdata: RData::A(Ipv4Addr::new(23, 192, 228, 84)),
        }],
        unparsed: Vec::new(),
    };

    assert_eq!(reply, expected);
}

#[test]
fn test_reply_to_example_serialization_roundtrip() {
    let data = fs::read("tests/example.query.bin")
        .expect("Failed to read example.query.bin");
    let query = parse_dns_query(&data).expect("Failed to parse DNS query");
    let reply = construct_reply(&query).expect("Should construct a reply");

    let reply_serialized = reply.serialize();
    let reply_deserialized = parse_dns_query(&reply_serialized).unwrap();

    assert_eq!(reply, reply_deserialized);
}
