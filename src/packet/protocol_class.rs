#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    IN, // 1 - Internet
    Other(u16),
}

impl Class {
    pub fn parse(qclass: u16) -> Class {
        match qclass {
            1 => Class::IN,
            n => Class::Other(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Class::IN => 1,
            Class::Other(n) => n,
        }
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Class::IN => write!(f, "IN"),
            Class::Other(n) => write!(f, "Class({})", n),
        }
    }
}
