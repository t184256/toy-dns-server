use super::dns_name::{parse_dns_name, serialize_dns_name};
use super::error::ParseError;
use super::protocol_class::Class;
use super::record_type::Type;
use bytes::{Buf as _, BufMut as _};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
    Other(Vec<u8>),
}

impl RData {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            RData::A(ip) => ip.octets().to_vec(),
            RData::AAAA(ip) => ip.octets().to_vec(),
            RData::NS(name) | RData::CNAME(name) => serialize_dns_name(name),
            RData::Other(data) => data.clone(),
        }
    }
}

impl std::fmt::Display for RData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RData::A(ip) => write!(f, "{}", ip),
            RData::AAAA(ip) => write!(f, "{}", ip),
            RData::NS(name) => write!(f, "{}", name),
            RData::CNAME(name) => write!(f, "{}", name),
            RData::Other(data) => write!(f, "{:x?}", data),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: Type,
    pub rclass: Class,
    pub ttl: u32,
    pub rdata: RData,
}

impl std::fmt::Display for DnsAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Answer {{ Name: {}, Type: {}, Class: {}, TTL: {}, Data: {} }}",
            self.name, self.rtype, self.rclass, self.ttl, self.rdata
        )
    }
}

fn parse_rdata(
    rtype: Type,
    rdlength: u16,
    buf: &mut &[u8],
) -> Result<RData, ParseError> {
    if buf.remaining() < rdlength as usize {
        return Err(ParseError::new(format!(
            "Not enough bytes for RDATA: {} < {}",
            buf.remaining(),
            rdlength
        )));
    }

    match rtype {
        Type::A => {
            if rdlength != 4 {
                return Err(ParseError::new(format!(
                    "Invalid A record length: {}",
                    rdlength
                )));
            }
            let a = buf.get_u8();
            let b = buf.get_u8();
            let c = buf.get_u8();
            let d = buf.get_u8();
            Ok(RData::A(Ipv4Addr::new(a, b, c, d)))
        }
        Type::AAAA => {
            if rdlength != 16 {
                return Err(ParseError::new(format!(
                    "Invalid AAAA record length: {}",
                    rdlength
                )));
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Ok(RData::AAAA(Ipv6Addr::from(octets)))
        }
        Type::NS | Type::CNAME => {
            let name = parse_dns_name(buf)?;
            match rtype {
                Type::NS => Ok(RData::NS(name)),
                Type::CNAME => Ok(RData::CNAME(name)),
                _ => unreachable!(),
            }
        }
        Type::Other(_) => {
            let mut data = vec![0u8; rdlength as usize];
            buf.copy_to_slice(&mut data);
            Ok(RData::Other(data))
        }
    }
}

impl DnsAnswer {
    pub fn serialize(&self) -> Vec<u8> {
        let rdata_bytes = self.rdata.serialize();
        let mut buf = Vec::with_capacity(
            1 + self.name.len() + 2 * 3 + 4 + rdata_bytes.len(),
        );
        buf.put_slice(&serialize_dns_name(&self.name));
        buf.put_u16(self.rtype.to_u16());
        buf.put_u16(self.rclass.to_u16());
        buf.put_u32(self.ttl);
        buf.put_u16(rdata_bytes.len() as u16);
        buf.put_slice(&rdata_bytes);
        buf
    }
}

pub fn parse_dns_answer(buf: &mut &[u8]) -> Result<DnsAnswer, ParseError> {
    let name = parse_dns_name(buf)?;

    if buf.remaining() < 10 {
        return Err(ParseError::new(format!(
            "Not enough bytes for TYPE, CLASS, TTL, and RDLENGTH: {} < 10",
            buf.remaining()
        )));
    }

    let rtype = Type::parse(buf.get_u16());
    let rclass = Class::parse(buf.get_u16());
    let ttl = buf.get_u32();
    let rdlength = buf.get_u16();

    let rdata = parse_rdata(rtype, rdlength, buf)?;

    Ok(DnsAnswer { name, rtype, rclass, ttl, rdata })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_a_record() {
        let mut buf: &[u8] = b"\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\
                               \x00\x3c\x00\x04\x5d\xb8\xd8\x22";
        let answer = parse_dns_answer(&mut buf).unwrap();
        assert_eq!(answer.name, "example.com");
        assert_eq!(answer.rtype, Type::A);
        assert_eq!(answer.rclass, Class::IN);
        assert_eq!(answer.ttl, 60);
        assert_eq!(answer.rdata, RData::A(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn test_serialize_a_record() {
        let answer = DnsAnswer {
            name: "example.com".to_string(),
            rtype: Type::A,
            rclass: Class::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        };
        let buf = answer.serialize();
        assert_eq!(
            buf,
            b"\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\
              \x04\x5d\xb8\xd8\x22"
        );
    }
}
