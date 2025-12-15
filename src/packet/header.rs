use super::error::ParseError;
use bytes::{Buf as _, BufMut as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    QUERY,
    IQUERY,
    STATUS,
    RESERVED,
}

fn parse_opcode(opcode: u8) -> OpCode {
    match opcode {
        0 => OpCode::QUERY,
        1 => OpCode::IQUERY,
        2 => OpCode::STATUS,
        _ => OpCode::RESERVED,
    }
}

impl OpCode {
    fn to_u8(self) -> u8 {
        match self {
            OpCode::QUERY => 0,
            OpCode::IQUERY => 1,
            OpCode::STATUS => 2,
            OpCode::RESERVED => 3,
        }
    }
}

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                OpCode::QUERY => "QUERY",
                OpCode::IQUERY => "IQUERY",
                OpCode::STATUS => "STATUS",
                OpCode::RESERVED => "RESERVED",
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    RESERVED,
}

fn parse_rcode(rcode: u8) -> RCode {
    match rcode {
        0 => RCode::NoError,
        1 => RCode::FormErr,
        2 => RCode::ServFail,
        3 => RCode::NXDomain,
        4 => RCode::NotImp,
        5 => RCode::Refused,
        _ => RCode::RESERVED,
    }
}

impl RCode {
    fn to_u8(self) -> u8 {
        match self {
            RCode::NoError => 0,
            RCode::FormErr => 1,
            RCode::ServFail => 2,
            RCode::NXDomain => 3,
            RCode::NotImp => 4,
            RCode::Refused => 5,
            RCode::RESERVED => 15,
        }
    }
}

impl std::fmt::Display for RCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RCode::NoError => "NoError",
                RCode::FormErr => "FormErr",
                RCode::ServFail => "ServFail",
                RCode::NXDomain => "NXDomain",
                RCode::NotImp => "NotImp",
                RCode::Refused => "Refused",
                RCode::RESERVED => "RESERVED",
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub response: bool,
    pub opcode: OpCode,
    pub authoritative_answer: bool,
    pub truncation: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub _reserved: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub rcode: RCode,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl DnsHeader {
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.put_u16(self.transaction_id);
        let byte2 = ((self.response as u8) << 7)
            | (self.opcode.to_u8() << 3)
            | ((self.authoritative_answer as u8) << 2)
            | ((self.truncation as u8) << 1)
            | (self.recursion_desired as u8);
        buf.put_u8(byte2);
        let byte3 = ((self.recursion_available as u8) << 7)
            | ((self._reserved as u8) << 6)
            | ((self.authenticated_data as u8) << 5)
            | ((self.checking_disabled as u8) << 4)
            | self.rcode.to_u8();
        buf.put_u8(byte3);
        buf.put_u16(self.qd_count);
        buf.put_u16(self.an_count);
        buf.put_u16(self.ns_count);
        buf.put_u16(self.ar_count);

        buf
    }
}

impl std::fmt::Display for DnsHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "DnsHeader {{")?;
        writeln!(f, "  * Transaction ID: 0x{:02x}", self.transaction_id)?;
        writeln!(f, "  * Response: {}", self.response)?;
        writeln!(f, "  * Opcode: {}", self.opcode)?;
        writeln!(f, "  * Authoritative Answer: {}", self.authoritative_answer)?;
        writeln!(f, "  * TrunCation: {}", self.truncation)?;
        writeln!(f, "  * Recursion Desired: {}", self.recursion_desired)?;
        writeln!(f, "  * Recursion Available: {}", self.recursion_available)?;
        writeln!(f, "  * Authenticated Data: {}", self.authenticated_data)?;
        writeln!(f, "  * Checking Disabled: {}", self.checking_disabled)?;
        writeln!(f, "  * RCode: {}", self.rcode)?;
        writeln!(f, "  * Questions: {}", self.qd_count)?;
        writeln!(f, "  * Answers: {}", self.an_count)?;
        writeln!(f, "  * Nameserver resource records: {}", self.ns_count)?;
        writeln!(f, "  * Additional records: {}", self.ar_count)?;
        write!(f, "}}")?;
        Ok(())
    }
}

pub fn parse_dns_header(buf: &mut &[u8]) -> Result<DnsHeader, ParseError> {
    // it's a learning project, so I'm doing it low-level for fun, with just Buf

    if buf.remaining() < 12 {
        return Err(ParseError::new(format!(
            "Not enough bytes for DNS header: {} bytes < 12",
            buf.remaining()
        )));
    }

    let transaction_id = buf.get_u16();
    let byte2 = buf.get_u8();
    let byte3 = buf.get_u8();
    let qd_count = buf.get_u16();
    let an_count = buf.get_u16();
    let ns_count = buf.get_u16();
    let ar_count = buf.get_u16();

    if (byte3 >> 4) & 1 == 1 {
        return Err(ParseError::new("Z bit must be 0, got 1".to_string()));
    }

    Ok(DnsHeader {
        transaction_id,
        response: (byte2 >> 7) & 1 == 1,
        opcode: parse_opcode((byte2 >> 3) & 0b1111),
        authoritative_answer: (byte2 >> 2) & 1 == 1,
        truncation: (byte2 >> 1) & 1 == 1,
        recursion_desired: byte2 & 1 == 1,
        recursion_available: (byte3 >> 7) == 1,
        _reserved: (byte3 >> 6) == 1,
        authenticated_data: (byte3 >> 5) == 1,
        checking_disabled: (byte3 >> 4) == 1,
        rcode: parse_rcode(byte3 & 0b1111),
        qd_count,
        an_count,
        ns_count,
        ar_count,
    })
}
