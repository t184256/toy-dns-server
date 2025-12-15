use bytes::{Buf as _, BufMut as _};
pub mod answer;
pub mod dns_name;
pub mod error;
pub mod header;
pub mod protocol_class;
pub mod question;
pub mod record_type;

pub use error::ParseError;

use answer::{DnsAnswer, parse_dns_answer};
use header::{DnsHeader, parse_dns_header};
use question::{DnsQuestion, parse_dns_question};

#[derive(Debug, PartialEq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    // TODO: not implemented yet: authority
    // TODO: not implemented yet: additional
    pub unparsed: Vec<u8>,
}

impl std::fmt::Display for DnsPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "DnsPacket {{")?;
        writeln!(f, "* {}", self.header)?;
        for question in &self.questions {
            writeln!(f, "* {}", question)?;
        }
        for answer in &self.answers {
            writeln!(f, "* {}", answer)?;
        }
        writeln!(f, "? Unparsed: {:x?}", self.unparsed)?;
        write!(f, "}}")?;
        Ok(())
    }
}

impl DnsPacket {
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.put_slice(&self.header.serialize());
        for question in &self.questions {
            buf.put_slice(&question.serialize());
        }
        for answer in &self.answers {
            buf.put_slice(&answer.serialize());
        }
        buf.put_slice(&self.unparsed);
        buf
    }
}

pub fn parse_dns_query(b: &[u8]) -> Result<DnsPacket, ParseError> {
    // it's a learning project, so I'm doing it low-level for fun, with just Buf

    let mut buf = b;
    let header = parse_dns_header(&mut buf)?;

    let mut questions = Vec::new();
    for _ in 0..header.qd_count {
        questions.push(parse_dns_question(&mut buf)?);
    }
    let mut answers = Vec::new();
    for _ in 0..header.an_count {
        answers.push(parse_dns_answer(&mut buf)?);
    }
    let unparsed = buf.copy_to_bytes(buf.remaining()).to_vec();

    Ok(DnsPacket { header, questions, answers, unparsed })
}
