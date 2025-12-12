use super::error::ParseError;
use bytes::{Buf as _, BufMut as _};

/// Example: "example.com" -> \x07example\x03com\x00
pub fn serialize_dns_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in name.split('.') {
        buf.put_u8(label.len() as u8);
        buf.put_slice(label.as_bytes());
    }
    buf.put_u8(0);
    buf
}

/// Example: \x07example\x03com\x00 -> "example.com"
pub fn parse_dns_name(buf: &mut &[u8]) -> Result<String, ParseError> {
    let mut labels = Vec::new();

    loop {
        if buf.is_empty() {
            return Err(ParseError::new(
                "Unexpected end of buffer while parsing DNS name".to_string(),
            ));
        }

        let len = buf.get_u8();

        // Check for compression (top 2 bits set)
        if len & 0xC0 != 0 {
            return Err(ParseError::new(
                "DNS name compression not supported".to_string(),
            ));
        }

        if len == 0 {
            break;
        }

        if buf.remaining() < len as usize {
            return Err(ParseError::new(format!(
                "Label length {} exceeds remaining buffer size {}",
                len,
                buf.remaining()
            )));
        }

        let mut label = vec![0; len as usize];
        buf.copy_to_slice(&mut label);

        let label_str = String::from_utf8(label).map_err(|e| {
            ParseError::new(format!("Invalid UTF-8 in DNS label: {}", e))
        })?;

        labels.push(label_str);
    }

    Ok(labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_name() {
        let mut buf: &[u8] = b"\x07example\x03com\x00";
        assert_eq!(parse_dns_name(&mut buf).unwrap(), "example.com");
    }

    #[test]
    fn test_serialize_dns_name() {
        let buf = serialize_dns_name("example.com");
        assert_eq!(buf, b"\x07example\x03com\x00");
    }
}
