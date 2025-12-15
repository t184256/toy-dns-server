#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    A,     // 1
    NS,    // 2
    CNAME, // 5
    AAAA,  // 28
    Other(u16),
}

impl Type {
    pub fn parse(qtype: u16) -> Type {
        match qtype {
            1 => Type::A,
            2 => Type::NS,
            5 => Type::CNAME,
            28 => Type::AAAA,
            n => Type::Other(n),
        }
    }
    pub fn to_u16(self) -> u16 {
        match self {
            Type::A => 1,
            Type::NS => 2,
            Type::CNAME => 5,
            Type::AAAA => 28,
            Type::Other(n) => n,
        }
    }
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::A => write!(f, "A"),
            Type::NS => write!(f, "NS"),
            Type::CNAME => write!(f, "CNAME"),
            Type::AAAA => write!(f, "AAAA"),
            Type::Other(n) => write!(f, "Type({})", n),
        }
    }
}
