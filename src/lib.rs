use std::io;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

mod packet;
mod zone_config;
use packet::ParseError;
pub use packet::answer::{DnsAnswer, RData};
pub use packet::header::{DnsHeader, OpCode, RCode};
pub use packet::protocol_class::Class;
pub use packet::question::DnsQuestion;
pub use packet::record_type::Type;
pub use packet::{DnsPacket, parse_dns_query};
pub use zone_config::{Record, Zone, ZoneConfig, find_record};

impl From<ParseError> for io::Error {
    fn from(e: ParseError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

pub fn construct_reply(
    config: &ZoneConfig,
    query: &DnsPacket,
) -> Option<DnsPacket> {
    let DnsPacket { header, questions, .. } = query;
    if header.response {
        return None;
    }

    let mut answers = Vec::new();
    let rcode = if questions.len() == 1 {
        let q = &questions[0];

        if q.qclass == Class::IN {
            let (records, ttl) = find_record(config, &q.qname, q.qtype);
            if records.is_empty() {
                RCode::NXDomain
            } else {
                answers.extend(records.into_iter().map(|record| DnsAnswer {
                    name: q.qname.clone(),
                    rclass: q.qclass,
                    rtype: q.qtype,
                    ttl,
                    rdata: record.rdata,
                }));
                RCode::NoError
            }
        } else {
            RCode::Refused
        }
    } else {
        RCode::NotImp
    };

    Some(DnsPacket {
        header: DnsHeader {
            transaction_id: header.transaction_id,
            response: true,
            opcode: header.opcode,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: header.recursion_desired,
            recursion_available: false,
            _reserved: false,
            authenticated_data: false,
            checking_disabled: false,
            rcode,
            qd_count: questions.len().try_into().unwrap_or(u16::MAX),
            an_count: answers.len().try_into().unwrap_or(u16::MAX),
            ns_count: 0, // No authority records
            ar_count: 0, // No additional records
        },
        questions: questions.clone(),
        answers,
        unparsed: Vec::new(),
    })
}

async fn process_udp(
    config: Arc<ZoneConfig>,
    socket: Arc<UdpSocket>,
    data: Vec<u8>,
    peer: std::net::SocketAddr,
) -> Result<(), io::Error> {
    let packet = parse_dns_query(&data)?;
    eprintln!("Received query: {packet}");

    if let Some(reply) = construct_reply(&config, &packet) {
        eprintln!("Sending back reply: {reply}");
        let sent = socket.send_to(&reply.serialize(), &peer).await?;
        eprintln!("Sent {sent} bytes back to {peer}");
    } else {
        eprintln!("Not answering that query");
    }
    Ok(())
}

pub async fn serve_udp(
    config: &ZoneConfig,
    listen: &str,
) -> Result<(), io::Error> {
    let socket = UdpSocket::bind(listen).await?;
    eprintln!("Listening on: {}...", socket.local_addr()?);
    let socket = Arc::new(socket);
    let config = Arc::new(config.clone());

    let mut tasks = JoinSet::new();
    let mut recv_buf = vec![0; 65535];

    loop {
        tokio::select! {
            // return on errors (may be a weird decision, but I was curious)
            Some(result) = tasks.join_next() => { result.unwrap()?; }
            // process datagrams
            recv_result = socket.recv_from(&mut recv_buf) => {
                let (size, peer) = recv_result?;
                eprintln!("Received {size} bytes from {peer}");
                tasks.spawn(process_udp(Arc::clone(&config),
                                        Arc::clone(&socket),  // clone sharing
                                        recv_buf[..size].to_vec(),  // copy
                                        peer));
            }
        }
    }
}
