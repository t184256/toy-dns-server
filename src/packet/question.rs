use super::dns_name::{parse_dns_name, serialize_dns_name};
use super::error::ParseError;
use bytes::{Buf as _, BufMut as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QType {
    A,     // 1
    NS,    // 2
    CNAME, // 5
    AAAA,  // 28
    Other(u16),
}

impl QType {
    pub fn parse(qtype: u16) -> QType {
        match qtype {
            1 => QType::A,
            2 => QType::NS,
            5 => QType::CNAME,
            28 => QType::AAAA,
            n => QType::Other(n),
        }
    }
    pub fn to_u16(self) -> u16 {
        match self {
            QType::A => 1,
            QType::NS => 2,
            QType::CNAME => 5,
            QType::AAAA => 28,
            QType::Other(n) => n,
        }
    }
}

impl std::fmt::Display for QType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QType::A => write!(f, "A"),
            QType::NS => write!(f, "NS"),
            QType::CNAME => write!(f, "CNAME"),
            QType::AAAA => write!(f, "AAAA"),
            QType::Other(n) => write!(f, "Type({})", n),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QClass {
    IN, // 1 - Internet
    Other(u16),
}

impl QClass {
    pub fn parse(qclass: u16) -> QClass {
        match qclass {
            1 => QClass::IN,
            n => QClass::Other(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            QClass::IN => 1,
            QClass::Other(n) => n,
        }
    }
}

impl std::fmt::Display for QClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QClass::IN => write!(f, "IN"),
            QClass::Other(n) => write!(f, "Class({})", n),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: QType,
    pub qclass: QClass,
}

impl std::fmt::Display for DnsQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Question {{ Name: {}, Type: {}, Class: {} }}",
            self.qname, self.qtype, self.qclass
        )
    }
}

impl DnsQuestion {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.qname.len() + 2 * 2);
        buf.put_slice(&serialize_dns_name(&self.qname));
        buf.put_u16(self.qtype.to_u16());
        buf.put_u16(self.qclass.to_u16());
        buf
    }
}

pub fn parse_dns_question(buf: &mut &[u8]) -> Result<DnsQuestion, ParseError> {
    let qname = parse_dns_name(buf)?;

    if buf.remaining() < 4 {
        return Err(ParseError::new(format!(
            "Not enough bytes for QTYPE and QCLASS: {} < 4",
            buf.remaining()
        )));
    }

    let qtype = QType::parse(buf.get_u16());
    let qclass = QClass::parse(buf.get_u16());

    Ok(DnsQuestion { qname, qtype, qclass })
}
