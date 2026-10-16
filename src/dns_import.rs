//! Loss-refusing import of the supported ValueDomain record text subset.
//! Output is a DNS-only migration candidate, never write authorization.
use crate::{Result, domain_name, error};
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Serialize)]
pub struct Record {
    #[serde(rename = "type")]
    pub record_type: &'static str,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    pub ttl: u32,
    pub proxied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<SrvData>,
}
#[derive(Debug, Serialize)]
pub struct SrvData {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

pub(crate) fn owner(zone: &str, input: &str) -> Result<String> {
    let name = if input == "@" {
        zone.to_owned()
    } else if input.ends_with('.') {
        input.trim_end_matches('.').to_lowercase()
    } else {
        format!("{}.{}", input.to_lowercase(), zone)
    };
    if name.len() > 253
        || !(name == zone || name.ends_with(&format!(".{zone}")))
        || name.split('.').enumerate().any(|(index, label)| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !(index == 0 && label == "*"
                    || label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        })
    {
        return Err(error("invalid_record_owner"));
    }
    Ok(name)
}
fn target(zone: &str, input: &str) -> Result<String> {
    domain_name(if input == "@" { zone } else { input })
}
fn number(input: &str) -> Result<u16> {
    input.parse().map_err(|_| error("invalid_record_number"))
}

pub fn parse(zone: &str, ttl: u32, text: &str) -> Result<Vec<Record>> {
    let zone = domain_name(zone)?;
    if !(60..=86400).contains(&ttl) {
        return Err(error("unsupported_import_ttl"));
    }
    if text.len() > 256 * 1024 {
        return Err(error("input_budget"));
    }
    let mut records = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if records.len() == 1000 {
            return Err(error("record_budget"));
        }
        let words: Vec<_> = line.split_whitespace().collect();
        let kind = words[0].to_ascii_lowercase();
        let mut record = Record {
            record_type: "A",
            name: zone.clone(),
            content: None,
            ttl,
            proxied: false,
            priority: None,
            data: None,
        };
        match kind.as_str() {
            "a" | "aaaa" | "cname" if words.len() == 3 => {
                record.name = owner(&zone, words[1])?;
                record.content = Some(match kind.as_str() {
                    "a" => {
                        record.record_type = "A";
                        words[2]
                            .parse::<Ipv4Addr>()
                            .map_err(|_| error("invalid_address"))?
                            .to_string()
                    }
                    "aaaa" => {
                        record.record_type = "AAAA";
                        words[2]
                            .parse::<Ipv6Addr>()
                            .map_err(|_| error("invalid_address"))?
                            .to_string()
                    }
                    _ => {
                        record.record_type = "CNAME";
                        target(&zone, words[2])?
                    }
                });
            }
            "mx" if words.len() == 3 || words.len() == 4 => {
                record.record_type = "MX";
                record.name = owner(&zone, words.get(3).copied().unwrap_or("@"))?;
                let priority = number(words[2])?;
                record.content = Some(if words[1] == "." {
                    if priority != 0 {
                        return Err(error("invalid_null_mx"));
                    }
                    ".".to_owned()
                } else {
                    target(&zone, words[1])?
                });
                record.priority = Some(priority);
            }
            "txt" => {
                let rest = line[words[0].len()..].trim_start();
                let (host, content) = if rest.starts_with('"') {
                    ("@", rest)
                } else {
                    let split = rest
                        .find(char::is_whitespace)
                        .ok_or_else(|| error("invalid_txt"))?;
                    (&rest[..split], rest[split..].trim_start())
                };
                // Preserve quotation/escape bytes. Complex multi-string forms require review.
                if content.len() < 2
                    || content.len() > 2048
                    || !content.starts_with('"')
                    || !content.ends_with('"')
                    || content[1..content.len() - 1].contains('"')
                {
                    return Err(error("unsupported_txt_encoding"));
                }
                record.record_type = "TXT";
                record.name = owner(&zone, host)?;
                record.content = Some(content.to_owned());
            }
            "srv" if words.len() == 6 => {
                record.record_type = "SRV";
                record.name = owner(&zone, words[1])?;
                record.data = Some(SrvData {
                    priority: number(words[2])?,
                    weight: number(words[3])?,
                    port: number(words[4])?,
                    target: target(&zone, words[5])?,
                });
            }
            _ => return Err(error("unsupported_record_syntax")),
        }
        records.push(record);
    }
    Ok(records)
}
