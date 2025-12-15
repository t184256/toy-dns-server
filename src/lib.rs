use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

mod packet;
use packet::ParseError;
pub use packet::answer::{DnsAnswer, RData};
pub use packet::header::{DnsHeader, OpCode, RCode};
pub use packet::protocol_class::Class;
pub use packet::question::DnsQuestion;
pub use packet::record_type::Type;
pub use packet::{DnsPacket, parse_dns_query};

impl From<ParseError> for io::Error {
    fn from(e: ParseError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

pub fn construct_reply(query: &DnsPacket) -> Option<DnsPacket> {
    let DnsPacket { header, questions, .. } = query;
    if header.response {
        return None;
    }

    let mut answers = Vec::new();
    let rcode = if questions.len() == 1 {
        let q = &questions[0];

        // Only meaningfully reply to A queries for example.com for now
        if q.qname == "example.com"
            && q.qtype == Type::A
            && q.qclass == Class::IN
        {
            answers.push(DnsAnswer {
                name: "example.com".to_string(),
                rclass: q.qclass,
                rtype: q.qtype,
                ttl: 5,
                rdata: RData::A(Ipv4Addr::new(23, 192, 228, 84)),
            });
            RCode::NoError
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
            qd_count: questions.len() as u16,
            an_count: answers.len() as u16,
            ns_count: 0, // No authority records
            ar_count: 0, // No additional records
        },
        questions: questions.clone(),
        answers,
        unparsed: Vec::new(),
    })
}

async fn process_udp(
    socket: Arc<UdpSocket>,
    data: Vec<u8>,
    peer: std::net::SocketAddr,
) -> Result<(), io::Error> {
    let packet = parse_dns_query(&data)?;
    eprintln!("Received query: {packet}");

    if let Some(reply) = construct_reply(&packet) {
        eprintln!("Sending back reply: {reply}");
        let sent = socket.send_to(&reply.serialize(), &peer).await?;
        eprintln!("Sent {sent} bytes back to {peer}");
    } else {
        eprintln!("Not answering that query");
    }
    Ok(())
}

pub async fn serve_udp(listen: &str) -> Result<(), io::Error> {
    let socket = UdpSocket::bind(&listen).await?;
    eprintln!("Listening on: {}...", socket.local_addr()?);
    let socket = Arc::new(socket);

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
                tasks.spawn(process_udp(Arc::clone(&socket),  // clone sharing
                                        recv_buf[..size].to_vec(),  // copy
                                        peer));
            }
        }
    }
}
