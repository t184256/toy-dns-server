use super::dns_name::{parse_dns_name, serialize_dns_name};
use super::error::ParseError;
use super::protocol_class::Class;
use super::record_type::Type;
use bytes::{Buf as _, BufMut as _};

#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: Type,
    pub qclass: Class,
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

    let qtype = Type::parse(buf.get_u16());
    let qclass = Class::parse(buf.get_u16());

    Ok(DnsQuestion { qname, qtype, qclass })
}
