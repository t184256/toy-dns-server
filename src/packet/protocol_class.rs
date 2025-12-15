#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    IN, // 1 - Internet
    Other(u16),
}

impl Class {
    pub fn parse(qclass: u16) -> Class {
        Class::from(qclass)
    }
}

impl From<u16> for Class {
    fn from(qclass: u16) -> Self {
        match qclass {
            1 => Class::IN,
            n => Class::Other(n),
        }
    }
}

impl From<Class> for u16 {
    fn from(c: Class) -> u16 {
        match c {
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
