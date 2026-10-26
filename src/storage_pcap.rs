use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    path::Path,
};

#[derive(Debug, Clone, Serialize)]
pub struct SqliteTableInfo {
    pub name: String,
    pub kind: String, // "table", "index", "view", "trigger"
    pub sql: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SqliteDbInfo {
    pub is_sqlite: bool,
    pub path: String,
    pub sha256: String,
    pub page_size: u32,
    pub change_counter: u32,
    pub user_version: u32,
    pub schema_cookie: u32,
    pub tables: Vec<SqliteTableInfo>,
    pub total_tables: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapPacketSummary {
    pub packet_index: usize,
    pub timestamp_sec: u32,
    pub timestamp_usec: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PcapCaptureInfo {
    pub is_pcap: bool,
    pub format: String, // "pcap_le", "pcap_be", "pcapng"
    pub path: String,
    pub sha256: String,
    pub total_packets: usize,
    pub total_bytes: u64,
    pub unique_ips: Vec<String>,
    pub unique_ports: Vec<u16>,
    pub protocols: Vec<String>,
}

pub struct StoragePcapInspector;

impl StoragePcapInspector {
    pub fn inspect_sqlite(path: &Path) -> Result<SqliteDbInfo, Box<dyn Error>> {
        let bytes = fs::read(path)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));

        if bytes.len() < 100 || &bytes[..16] != b"SQLite format 3\0" {
            return Ok(SqliteDbInfo {
                is_sqlite: false,
                path: path.to_string_lossy().to_string(),
                sha256,
                page_size: 0,
                change_counter: 0,
                user_version: 0,
                schema_cookie: 0,
                tables: Vec::new(),
                total_tables: 0,
            });
        }

        let raw_page_size = u16::from_be_bytes(bytes[16..18].try_into()?);
        let page_size = if raw_page_size == 1 { 65536 } else { raw_page_size as u32 };
        let change_counter = u32::from_be_bytes(bytes[24..28].try_into()?);
        let schema_cookie = u32::from_be_bytes(bytes[40..44].try_into()?);
        let user_version = u32::from_be_bytes(bytes[60..64].try_into()?);

        // Scan page 1 or whole database for CREATE TABLE / INDEX statements
        let mut tables = Vec::new();
        let text = String::from_utf8_lossy(&bytes);
        let mut idx = 0;

        while let Some(pos) = text[idx..].find("CREATE ") {
            let abs_pos = idx + pos;
            let sub = &text[abs_pos..];
            if let Some(semicolon) = sub.find(';') {
                let stmt = &sub[..semicolon];
                let tokens: Vec<&str> = stmt.split_whitespace().collect();
                if tokens.len() >= 3 {
                    let kind = tokens[1].to_lowercase();
                    if kind == "table" || kind == "index" || kind == "view" || kind == "trigger" {
                        let raw_name = tokens[2].trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == '[' || c == ']');
                        let name = raw_name.split('(').next().unwrap_or(raw_name).to_string();
                        if !tables.iter().any(|t: &SqliteTableInfo| t.name == name) {
                            tables.push(SqliteTableInfo {
                                name,
                                kind,
                                sql: Some(stmt.to_string()),
                            });
                        }
                    }
                }
                idx = abs_pos + semicolon + 1;
            } else {
                idx = abs_pos + 7;
            }
        }

        let total_tables = tables.len();
        Ok(SqliteDbInfo {
            is_sqlite: true,
            path: path.to_string_lossy().to_string(),
            sha256,
            page_size,
            change_counter,
            user_version,
            schema_cookie,
            tables,
            total_tables,
        })
    }

    pub fn inspect_pcap(path: &Path) -> Result<PcapCaptureInfo, Box<dyn Error>> {
        let bytes = fs::read(path)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));

        if bytes.len() < 24 {
            return Err("File too small for PCAP".into());
        }

        let magic = &bytes[..4];
        let (is_le, format) = if magic == b"\xd4\xc3\xb2\xa1" {
            (true, "pcap_le".to_string())
        } else if magic == b"\xa1\xb2\xc3\xd4" {
            (false, "pcap_be".to_string())
        } else if magic == b"\x4d\x3c\xb2\xa1" {
            (true, "pcap_nanosecond_le".to_string())
        } else if magic == b"\xa1\xb2\x3c\x4d" {
            (false, "pcap_nanosecond_be".to_string())
        } else if magic == b"\x0a\x0d\x0d\x0a" {
            // PCAPNG
            return Ok(PcapCaptureInfo {
                is_pcap: true,
                format: "pcapng".to_string(),
                path: path.to_string_lossy().to_string(),
                sha256,
                total_packets: 0,
                total_bytes: bytes.len() as u64,
                unique_ips: Vec::new(),
                unique_ports: Vec::new(),
                protocols: vec!["pcapng_container".into()],
            });
        } else {
            return Err("Unknown PCAP format or signature".into());
        };

        let mut offset = 24;
        let mut total_packets = 0;
        let mut total_bytes = 0u64;
        let mut ips = BTreeSet::new();
        let mut ports = BTreeSet::new();
        let mut protos = BTreeSet::new();

        while offset + 16 <= bytes.len() {
            let cap_len = if is_le {
                u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into()?) as usize
            } else {
                u32::from_be_bytes(bytes[offset + 8..offset + 12].try_into()?) as usize
            };

            offset += 16;
            if offset + cap_len > bytes.len() {
                break;
            }

            let pkt_data = &bytes[offset..offset + cap_len];
            total_packets += 1;
            total_bytes += cap_len as u64;

            // Basic Ethernet frame parsing (14 bytes header)
            if pkt_data.len() >= 14 {
                let ether_type = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
                if ether_type == 0x0800 && pkt_data.len() >= 34 { // IPv4
                    let src_ip = format!("{}.{}.{}.{}", pkt_data[26], pkt_data[27], pkt_data[28], pkt_data[29]);
                    let dst_ip = format!("{}.{}.{}.{}", pkt_data[30], pkt_data[31], pkt_data[32], pkt_data[33]);
                    ips.insert(src_ip);
                    ips.insert(dst_ip);

                    let proto_num = pkt_data[23];
                    match proto_num {
                        6 => {
                            protos.insert("TCP".to_string());
                            if pkt_data.len() >= 38 {
                                let sport = u16::from_be_bytes([pkt_data[34], pkt_data[35]]);
                                let dport = u16::from_be_bytes([pkt_data[36], pkt_data[37]]);
                                ports.insert(sport);
                                ports.insert(dport);
                            }
                        }
                        17 => {
                            protos.insert("UDP".to_string());
                            if pkt_data.len() >= 38 {
                                let sport = u16::from_be_bytes([pkt_data[34], pkt_data[35]]);
                                let dport = u16::from_be_bytes([pkt_data[36], pkt_data[37]]);
                                ports.insert(sport);
                                ports.insert(dport);
                            }
                        }
                        1 => { protos.insert("ICMP".to_string()); }
                        _ => { protos.insert(format!("IP_proto_{}", proto_num)); }
                    }
                } else if ether_type == 0x86dd && pkt_data.len() >= 54 { // IPv6
                    protos.insert("IPv6".to_string());
                } else if ether_type == 0x0806 {
                    protos.insert("ARP".to_string());
                }
            }

            offset += cap_len;
        }

        Ok(PcapCaptureInfo {
            is_pcap: true,
            format,
            path: path.to_string_lossy().to_string(),
            sha256,
            total_packets,
            total_bytes,
            unique_ips: ips.into_iter().collect(),
            unique_ports: ports.into_iter().collect(),
            protocols: protos.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_invalid() {
        let fake = b"Not a sqlite file";
        let temp = std::env::temp_dir().join("test_not_sqlite.db");
        fs::write(&temp, fake).unwrap();
        let res = StoragePcapInspector::inspect_sqlite(&temp).unwrap();
        assert!(!res.is_sqlite);
        let _ = fs::remove_file(temp);
    }
}
