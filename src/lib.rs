use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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

async fn process_tcp(
    config: Arc<ZoneConfig>,
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
) -> Result<(), io::Error> {
    loop {
        // length prefix
        let length = match stream.read_u16().await {
            Ok(len) => len,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                eprintln!("TCP connection closed by {peer}");
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        let mut data = vec![0u8; length as usize];
        stream.read_exact(&mut data).await?;
        eprintln!("Received {length} bytes from {peer} (TCP)");

        let packet = parse_dns_query(&data)?;
        eprintln!("Received query: {packet}");
        if let Some(reply) = construct_reply(&config, &packet) {
            eprintln!("Sending back reply: {reply}");
            let reply_bytes = reply.serialize();
            let reply_len = reply_bytes.len() as u16;
            stream.write_u16(reply_len).await?; // length prefix
            stream.write_all(&reply_bytes).await?;
            stream.flush().await?;
            eprintln!("Sent {} bytes back to {peer} (TCP)", reply_len);
        } else {
            eprintln!("Not answering that query");
        }
    }
}

pub async fn serve(config: &ZoneConfig, listen: &str) -> Result<(), io::Error> {
    let udp_socket = UdpSocket::bind(listen).await?;
    let tcp_listener = TcpListener::bind(listen).await?;

    eprintln!("Listening on {} (UDP)...", udp_socket.local_addr()?);
    eprintln!("Listening on {} (TCP)...", tcp_listener.local_addr()?);

    let udp_socket = Arc::new(udp_socket);
    let config = Arc::new(config.clone());

    let mut tasks = JoinSet::new();
    let mut recv_buf = vec![0; 65535];

    loop {
        tokio::select! {
            // return on errors (may be a weird decision, but I was curious)
            Some(result) = tasks.join_next() => { result.unwrap()?; }
            // process UDP datagrams
            recv_result = udp_socket.recv_from(&mut recv_buf) => {
                let (size, peer) = recv_result?;
                eprintln!("Received {size} bytes from {peer} (UDP)");
                tasks.spawn(process_udp(Arc::clone(&config),
                                        Arc::clone(&udp_socket),
                                        recv_buf[..size].to_vec(),
                                        peer));
            }
            // accept TCP connections
            accept_result = tcp_listener.accept() => {
                let (stream, peer) = accept_result?;
                eprintln!("Accepted TCP connection from {peer}");
                tasks.spawn(process_tcp(Arc::clone(&config), stream, peer));
            }
        }
    }
}
