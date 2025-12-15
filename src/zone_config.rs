use crate::packet::answer::RData;
use crate::packet::record_type::Type;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Deserialize)]
pub struct ZoneConfig {
    #[serde(flatten)]
    pub zones: HashMap<String, Zone>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    #[serde(default)]
    pub ttl: Option<u32>,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub name: String,
    pub record_type: Type,
    pub rdata: RData,
}

#[derive(Deserialize)]
struct RecordHelper {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    address: String,
}

impl<'de> Deserialize<'de> for Record {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = RecordHelper::deserialize(deserializer)?;

        let record_type = match helper.record_type.as_str() {
            "A" => Type::A,
            "NS" => Type::NS,
            "CNAME" => Type::CNAME,
            "AAAA" => Type::AAAA,
            _ => {
                return Err(serde::de::Error::unknown_variant(
                    &helper.record_type,
                    &["A", "NS", "CNAME", "AAAA"],
                ));
            }
        };

        let rdata = match record_type {
            Type::A => {
                let ip: Ipv4Addr = helper.address.parse().map_err(|e| {
                    serde::de::Error::custom(format!(
                        "Invalid IPv4 address '{}': {}",
                        helper.address, e
                    ))
                })?;
                RData::A(ip)
            }
            Type::AAAA => {
                let ip: Ipv6Addr = helper.address.parse().map_err(|e| {
                    serde::de::Error::custom(format!(
                        "Invalid IPv6 address '{}': {}",
                        helper.address, e
                    ))
                })?;
                RData::AAAA(ip)
            }
            Type::NS => RData::NS(helper.address),
            Type::CNAME => RData::CNAME(helper.address),
            Type::Other(_) => {
                return Err(serde::de::Error::custom(
                    "Other type not supported in config",
                ));
            }
        };

        Ok(Record { name: helper.name, record_type, rdata })
    }
}

// TODO: return multiple answers
// TODO: make an iterator
pub fn find_record(
    config: &ZoneConfig,
    domain: &str,
    record_type: Type,
) -> Option<Record> {
    for (zone_name, zone) in &config.zones {
        if !domain.ends_with(zone_name.as_str()) {
            continue; // optimization
        }
        for record in &zone.records {
            let combined_name = if record.name.is_empty() {
                zone_name.clone()
            } else {
                format!("{}.{}", record.name, zone_name)
            };
            if combined_name == domain && record.record_type == record_type {
                return Some(record.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_zone() {
        let yaml = std::fs::read_to_string("tests/example_zone.yaml")
            .expect("Failed to read example zone file");

        let config: ZoneConfig =
            serde_yaml::from_str(&yaml).expect("Failed to parse zone config");

        let result = find_record(&config, "example.com", Type::A);
        assert!(result.is_some());
        let record = result.unwrap();
        assert_eq!(record.name, "");
        assert_eq!(record.record_type, Type::A);
        assert!(
            record.rdata == RData::A("23.192.228.80".parse().unwrap())
                || record.rdata == RData::A("23.192.228.84".parse().unwrap())
        );

        let result = find_record(&config, "subdomain.example.org", Type::A);
        assert_eq!(
            result,
            Some(Record {
                name: "subdomain".to_string(),
                record_type: Type::A,
                rdata: RData::A("172.66.157.88".parse().unwrap()),
            })
        );

        let result = find_record(&config, "nonexistent.com", Type::A);
        assert_eq!(result, None);
    }
}
