use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use toy_dns_server::{
    Class, DnsAnswer, DnsHeader, DnsPacket, DnsQuestion, OpCode, RCode, RData,
    Type, ZoneConfig, construct_reply, parse_dns_query,
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
            qtype: Type::A,
            qclass: Class::IN,
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
    let yaml = fs::read_to_string("tests/example_zone.yaml")
        .expect("Failed to read example zone file");
    let config: ZoneConfig =
        serde_yaml::from_str(&yaml).expect("Failed to parse zone config");

    let data = fs::read("tests/example.query.bin")
        .expect("Failed to read example.query.bin");
    let query = parse_dns_query(&data).expect("Failed to parse DNS query");
    let reply =
        construct_reply(&config, &query).expect("Should construct a reply");

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
            an_count: 2,
            ns_count: 0,
            ar_count: 0,
        },
        questions: vec![DnsQuestion {
            qname: "example.com".to_string(),
            qtype: Type::A,
            qclass: Class::IN,
        }],
        answers: vec![
            DnsAnswer {
                name: "example.com".to_string(),
                rclass: Class::IN,
                rtype: Type::A,
                ttl: 5,
                rdata: RData::A(Ipv4Addr::new(23, 192, 228, 80)),
            },
            DnsAnswer {
                name: "example.com".to_string(),
                rclass: Class::IN,
                rtype: Type::A,
                ttl: 5,
                rdata: RData::A(Ipv4Addr::new(23, 192, 228, 84)),
            },
        ],
        unparsed: Vec::new(),
    };

    assert_eq!(reply, expected);
}

#[test]
fn test_reply_to_example_serialization_roundtrip() {
    let yaml = fs::read_to_string("tests/example_zone.yaml")
        .expect("Failed to read example zone file");
    let config: ZoneConfig =
        serde_yaml::from_str(&yaml).expect("Failed to parse zone config");

    let data = fs::read("tests/example.query.bin")
        .expect("Failed to read example.query.bin");
    let query = parse_dns_query(&data).expect("Failed to parse DNS query");
    let reply =
        construct_reply(&config, &query).expect("Should construct a reply");

    let reply_serialized = reply.serialize();
    let reply_deserialized = parse_dns_query(&reply_serialized).unwrap();

    assert_eq!(reply, reply_deserialized);
}

#[test]
fn test_reply_aaaa_query() {
    let yaml = fs::read_to_string("tests/example_zone.yaml")
        .expect("Failed to read example zone file");
    let config: ZoneConfig =
        serde_yaml::from_str(&yaml).expect("Failed to parse zone config");

    let query = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x1234,
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
            ar_count: 0,
        },
        questions: vec![DnsQuestion {
            qname: "example.com".to_string(),
            qtype: Type::AAAA,
            qclass: Class::IN,
        }],
        answers: vec![],
        unparsed: vec![],
    };

    let reply =
        construct_reply(&config, &query).expect("Should construct a reply");

    let expected = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x1234,
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
            an_count: 2,
            ns_count: 0,
            ar_count: 0,
        },
        questions: vec![DnsQuestion {
            qname: "example.com".to_string(),
            qtype: Type::AAAA,
            qclass: Class::IN,
        }],
        answers: vec![
            DnsAnswer {
                name: "example.com".to_string(),
                rclass: Class::IN,
                rtype: Type::AAAA,
                ttl: 5,
                rdata: RData::AAAA(Ipv6Addr::new(
                    0x2600, 0x1406, 0x5e00, 0x6, 0, 0, 0x17ce, 0xbc1b,
                )),
            },
            DnsAnswer {
                name: "example.com".to_string(),
                rclass: Class::IN,
                rtype: Type::AAAA,
                ttl: 5,
                rdata: RData::AAAA(Ipv6Addr::new(
                    0x2600, 0x1406, 0xbc00, 0x53, 0, 0, 0xb81e, 0x94c8,
                )),
            },
        ],
        unparsed: vec![],
    };

    assert_eq!(reply, expected);
}

#[test]
fn test_reply_ns_query() {
    let yaml = fs::read_to_string("tests/example_zone.yaml")
        .expect("Failed to read example zone file");
    let config: ZoneConfig =
        serde_yaml::from_str(&yaml).expect("Failed to parse zone config");

    let query = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x1234,
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
            ar_count: 0,
        },
        questions: vec![DnsQuestion {
            qname: "example.com".to_string(),
            qtype: Type::NS,
            qclass: Class::IN,
        }],
        answers: vec![],
        unparsed: vec![],
    };

    let reply =
        construct_reply(&config, &query).expect("Should construct a reply");

    let expected = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x1234,
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
            an_count: 2,
            ns_count: 0,
            ar_count: 0,
        },
        questions: vec![DnsQuestion {
            qname: "example.com".to_string(),
            qtype: Type::NS,
            qclass: Class::IN,
        }],
        answers: vec![
            DnsAnswer {
                name: "example.com".to_string(),
                rclass: Class::IN,
                rtype: Type::NS,
                ttl: 5,
                rdata: RData::NS("a.iana-servers.net.".to_string()),
            },
            DnsAnswer {
                name: "example.com".to_string(),
                rclass: Class::IN,
                rtype: Type::NS,
                ttl: 5,
                rdata: RData::NS("b.iana-servers.net.".to_string()),
            },
        ],
        unparsed: vec![],
    };

    assert_eq!(reply, expected);
}

#[test]
fn test_reply_example_org_custom_ttl() {
    let yaml = fs::read_to_string("tests/example_zone.yaml")
        .expect("Failed to read example zone file");
    let config: ZoneConfig =
        serde_yaml::from_str(&yaml).expect("Failed to parse zone config");

    let query = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x5678,
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
            ar_count: 0,
        },
        questions: vec![DnsQuestion {
            qname: "example.org".to_string(),
            qtype: Type::A,
            qclass: Class::IN,
        }],
        answers: vec![],
        unparsed: vec![],
    };

    let reply =
        construct_reply(&config, &query).expect("Should construct a reply");

    let expected = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x5678,
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
            qname: "example.org".to_string(),
            qtype: Type::A,
            qclass: Class::IN,
        }],
        answers: vec![DnsAnswer {
            name: "example.org".to_string(),
            rclass: Class::IN,
            rtype: Type::A,
            ttl: 7,
            rdata: RData::A(Ipv4Addr::new(104, 20, 26, 109)),
        }],
        unparsed: vec![],
    };

    assert_eq!(reply, expected);
}

#[test]
fn test_reply_subdomain_query() {
    let yaml = fs::read_to_string("tests/example_zone.yaml")
        .expect("Failed to read example zone file");
    let config: ZoneConfig =
        serde_yaml::from_str(&yaml).expect("Failed to parse zone config");

    let query = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x9abc,
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
            ar_count: 0,
        },
        questions: vec![DnsQuestion {
            qname: "subdomain.example.org".to_string(),
            qtype: Type::A,
            qclass: Class::IN,
        }],
        answers: vec![],
        unparsed: vec![],
    };

    let reply =
        construct_reply(&config, &query).expect("Should construct a reply");

    let expected = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x9abc,
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
            qname: "subdomain.example.org".to_string(),
            qtype: Type::A,
            qclass: Class::IN,
        }],
        answers: vec![DnsAnswer {
            name: "subdomain.example.org".to_string(),
            rclass: Class::IN,
            rtype: Type::A,
            ttl: 7,
            rdata: RData::A(Ipv4Addr::new(172, 66, 157, 88)),
        }],
        unparsed: vec![],
    };

    assert_eq!(reply, expected);
}

#[test]
fn test_reply_cname_query() {
    let yaml = fs::read_to_string("tests/example_zone.yaml")
        .expect("Failed to read example zone file");
    let config: ZoneConfig =
        serde_yaml::from_str(&yaml).expect("Failed to parse zone config");

    let query = DnsPacket {
        header: DnsHeader {
            transaction_id: 0xdef0,
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
            ar_count: 0,
        },
        questions: vec![DnsQuestion {
            qname: "alias.example.org".to_string(),
            qtype: Type::CNAME,
            qclass: Class::IN,
        }],
        answers: vec![],
        unparsed: vec![],
    };

    let reply =
        construct_reply(&config, &query).expect("Should construct a reply");

    let expected = DnsPacket {
        header: DnsHeader {
            transaction_id: 0xdef0,
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
            qname: "alias.example.org".to_string(),
            qtype: Type::CNAME,
            qclass: Class::IN,
        }],
        answers: vec![DnsAnswer {
            name: "alias.example.org".to_string(),
            rclass: Class::IN,
            rtype: Type::CNAME,
            ttl: 7,
            rdata: RData::CNAME("something-else.example.org".to_string()),
        }],
        unparsed: vec![],
    };

    assert_eq!(reply, expected);
}
