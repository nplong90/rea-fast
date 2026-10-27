use serde_json::{Value, json};
use std::fs;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

const MAX_CDP_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_CDP_WS_FRAME_BYTES: u64 = 16 * 1024 * 1024;

fn checked_ws_payload_len(length: u64) -> Result<usize, String> {
    if length > MAX_CDP_WS_FRAME_BYTES {
        return Err("CDP WebSocket frame exceeds 16 MiB limit".to_string());
    }
    usize::try_from(length).map_err(|_| "WebSocket frame length overflows usize".to_string())
}

fn parse_cdp_content_length(headers: &str) -> Result<usize, String> {
    let mut length = None;
    for line in headers.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("Duplicate Content-Length in CDP response".to_string());
            }
            let number: u64 = value
                .trim()
                .parse()
                .map_err(|_| "Invalid Content-Length in CDP response".to_string())?;
            length = Some(checked_http_length(number)?);
        }
    }
    length.ok_or_else(|| "Missing Content-Length in CDP response".to_string())
}

fn checked_http_length(length: u64) -> Result<usize, String> {
    if length > MAX_CDP_HTTP_BODY_BYTES as u64 {
        return Err("CDP HTTP response exceeds 2 MiB limit".to_string());
    }
    usize::try_from(length).map_err(|_| "CDP Content-Length overflows usize".to_string())
}

pub fn fetch_cdp_targets(endpoint: &str) -> Result<Vec<Value>, String> {
    let cleaned = endpoint
        .trim_start_matches("http://")
        .trim_start_matches("ws://");
    let host_port = cleaned.split('/').next().unwrap_or("127.0.0.1:9222");

    let mut stream = TcpStream::connect_timeout(
        &host_port
            .parse()
            .map_err(|e| format!("Invalid address {host_port}: {e}"))?,
        Duration::from_millis(500),
    )
    .map_err(|e| format!("Cannot connect to CDP at {host_port}: {e}"))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap_or(());
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap_or(());

    let req = format!("GET /json/list HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("Failed to send HTTP: {e}"))?;

    let mut header_bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !header_bytes.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .map_err(|e| format!("Header read failed: {e}"))?;
        header_bytes.push(byte[0]);
        if header_bytes.len() > 16384 {
            return Err("HTTP header too large".to_string());
        }
    }

    let header_str = String::from_utf8_lossy(&header_bytes);
    let content_length = parse_cdp_content_length(&header_str)?;
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        stream
            .read_exact(&mut body)
            .map_err(|e| format!("Body read failed: {e}"))?;
    }

    serde_json::from_slice::<Vec<Value>>(&body).map_err(|e| format!("JSON parse error: {e}"))
}

pub fn list_browser_targets(args: &Value) -> Value {
    let endpoint = args
        .get("cdp_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("http://127.0.0.1:9222");
    match fetch_cdp_targets(endpoint) {
        Ok(targets) => json!({
            "status": "complete",
            "endpoint": endpoint,
            "target_count": targets.len(),
            "targets": targets
        }),
        Err(e) => json!({
            "status": "unavailable",
            "endpoint": endpoint,
            "message": format!("CDP browser not reachable: {e}"),
            "hint": "Launch Chrome/Brave/Electron with --remote-debugging-port=9222"
        }),
    }
}

pub fn list_electron_targets(args: &Value) -> Value {
    let endpoint = args
        .get("cdp_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("http://127.0.0.1:9222");
    match fetch_cdp_targets(endpoint) {
        Ok(targets) => {
            let file_targets: Vec<Value> = targets
                .into_iter()
                .filter(|t| {
                    t.get("url")
                        .and_then(|u| u.as_str())
                        .map(|s| s.starts_with("file://"))
                        .unwrap_or(false)
                })
                .collect();
            json!({
                "status": "complete",
                "endpoint": endpoint,
                "target_count": file_targets.len(),
                "targets": file_targets
            })
        }
        Err(e) => json!({
            "status": "unavailable",
            "endpoint": endpoint,
            "message": format!("Electron CDP not reachable: {e}"),
            "hint": "Launch Electron with --remote-debugging-port=9222"
        }),
    }
}

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn secure_random_bytes(out: &mut [u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut source = fs::File::open("/dev/urandom")
            .map_err(|e| format!("OS randomness unavailable: {e}"))?;
        source
            .read_exact(out)
            .map_err(|e| format!("OS randomness failed: {e}"))
    }
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        unsafe extern "system" {
            fn BCryptGenRandom(
                algorithm: *mut std::ffi::c_void,
                buffer: *mut u8,
                buffer_length: u32,
                flags: u32,
            ) -> i32;
        }
        let length = u32::try_from(out.len()).map_err(|_| "Random buffer too large")?;
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG; nonnegative NTSTATUS means success.
        let status = unsafe {
            BCryptGenRandom(std::ptr::null_mut(), out.as_mut_ptr(), length, 0x2)
        };
        if status < 0 {
            Err(format!("Windows system randomness failed: {status}"))
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = out;
        Err("Cryptographic OS random generator is unavailable on this platform".to_string())
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for block in bytes.chunks(3) {
        let value = (u32::from(block[0]) << 16)
            | (u32::from(*block.get(1).unwrap_or(&0)) << 8)
            | u32::from(*block.get(2).unwrap_or(&0));
        result.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        result.push(if block.len() >= 2 {
            ALPHABET[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        result.push(if block.len() >= 3 {
            ALPHABET[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    result
}

/// SHA-1 is used only for the RFC 6455 public handshake challenge.
/// It is not a signature, password hash, or message authentication.
fn websocket_sha1(input: &[u8]) -> [u8; 20] {
    let mut data = input.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bits.to_be_bytes());
    let mut h = [0x67452301u32, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    for chunk in data.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (i, word) in words.iter_mut().take(16).enumerate() {
            let at = i * 4;
            *word = u32::from_be_bytes(chunk[at..at + 4].try_into().unwrap());
        }
        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16])
                .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, word) in words.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (dst, value) in h.iter_mut().zip([a, b, c, d, e]) {
            *dst = dst.wrapping_add(value);
        }
    }
    let mut digest = [0u8; 20];
    for (out, value) in digest.chunks_exact_mut(4).zip(h) {
        out.copy_from_slice(&value.to_be_bytes());
    }
    digest
}

fn websocket_accept_value(key: &str) -> String {
    let mut challenge = String::with_capacity(key.len() + WEBSOCKET_GUID.len());
    challenge.push_str(key);
    challenge.push_str(WEBSOCKET_GUID);
    encode_base64(&websocket_sha1(challenge.as_bytes()))
}

fn validate_websocket_handshake(headers: &str, expected: &str) -> Result<(), String> {
    let mut lines = headers.lines();
    let status = lines.next().unwrap_or("").trim_end_matches('\r');
    if !status.starts_with("HTTP/1.1 101 ") {
        return Err("WebSocket upgrade did not return HTTP 101".to_string());
    }
    let mut accepted = None;
    let mut upgraded = false;
    let mut connection = false;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let name = key.trim().to_ascii_lowercase();
            let value = value.trim();
            match name.as_str() {
                "sec-websocket-accept" => {
                    if accepted.replace(value.to_string()).is_some() {
                        return Err("Duplicate Sec-WebSocket-Accept".to_string());
                    }
                }
                "upgrade" => upgraded = value.eq_ignore_ascii_case("websocket"),
                "connection" => {
                    connection = value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
                }
                _ => {}
            }
        }
    }
    if !upgraded || !connection || accepted.as_deref() != Some(expected) {
        return Err("Invalid WebSocket upgrade headers or challenge response".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------
// Native RFC 6455 WebSocket Client (Zero Dependency)
// ---------------------------------------------------------

pub struct CdpSession {
    stream: TcpStream,
    next_id: u64,
}

impl CdpSession {
    pub fn connect(ws_url: &str) -> Result<Self, String> {
        let cleaned = ws_url
            .trim_start_matches("ws://")
            .trim_start_matches("http://");
        let (host_port, path) = match cleaned.find('/') {
            Some(idx) => (&cleaned[..idx], &cleaned[idx..]),
            None => (cleaned, "/"),
        };

        let mut stream = TcpStream::connect_timeout(
            &host_port
                .parse()
                .map_err(|e| format!("Invalid address {host_port}: {e}"))?,
            Duration::from_millis(1500),
        )
        .map_err(|e| format!("Cannot connect to WebSocket at {host_port}: {e}"))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap_or(());
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap_or(());

        // RFC 6455 uses a fresh unpredictable 16-byte client challenge.
        let mut challenge = [0u8; 16];
        secure_random_bytes(&mut challenge)?;
        let client_key = encode_base64(&challenge);
        let expected_accept = websocket_accept_value(&client_key);
        let handshake = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host_port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {client_key}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(handshake.as_bytes())
            .map_err(|e| format!("Handshake write failed: {e}"))?;

        // Read handshake response headers
        let mut response_buf = Vec::new();
        let mut byte = [0u8; 1];
        while !response_buf.ends_with(b"\r\n\r\n") {
            stream
                .read_exact(&mut byte)
                .map_err(|e| format!("Handshake read failed: {e}"))?;
            response_buf.push(byte[0]);
            if response_buf.len() > 8192 {
                return Err("WebSocket handshake response too large".to_string());
            }
        }

        let resp_str = String::from_utf8_lossy(&response_buf);
        validate_websocket_handshake(&resp_str, &expected_accept)?;

        Ok(Self { stream, next_id: 1 })
    }

    pub fn send_message(&mut self, text: &str) -> Result<(), String> {
        let payload = text.as_bytes();
        let len = payload.len();
        checked_ws_payload_len(len as u64)?;
        let mut header = Vec::with_capacity(14);
        header.push(0x81); // FIN = 1, Opcode = 1 (Text)

        let mut mask_key = [0u8; 4];
        secure_random_bytes(&mut mask_key)?;
        if len < 126 {
            header.push(0x80 | (len as u8));
        } else if len <= 65535 {
            header.push(0x80 | 126);
            header.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            header.push(0x80 | 127);
            header.extend_from_slice(&(len as u64).to_be_bytes());
        }
        header.extend_from_slice(&mask_key);

        let mut masked = Vec::with_capacity(len);
        for (i, &b) in payload.iter().enumerate() {
            masked.push(b ^ mask_key[i % 4]);
        }

        self.stream
            .write_all(&header)
            .map_err(|e| format!("Frame header write error: {e}"))?;
        self.stream
            .write_all(&masked)
            .map_err(|e| format!("Frame payload write error: {e}"))?;
        self.stream
            .flush()
            .map_err(|e| format!("Flush error: {e}"))?;
        Ok(())
    }

    pub fn read_message(&mut self) -> Result<String, String> {
        let mut header = [0u8; 2];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| format!("WS read error: {e}"))?;
        let opcode = header[0] & 0x0F;
        let masked = (header[1] & 0x80) != 0;
        let len_code = (header[1] & 0x7F) as usize;

        let payload_len = match len_code {
            126 => {
                let mut buf = [0u8; 2];
                self.stream
                    .read_exact(&mut buf)
                    .map_err(|e| format!("WS len16 read error: {e}"))?;
                u16::from_be_bytes(buf) as usize
            }
            127 => {
                let mut buf = [0u8; 8];
                self.stream
                    .read_exact(&mut buf)
                    .map_err(|e| format!("WS len64 read error: {e}"))?;
                checked_ws_payload_len(u64::from_be_bytes(buf))?
            }
            n => n,
        };

        checked_ws_payload_len(payload_len as u64)?;

        let mask_key = if masked {
            let mut key = [0u8; 4];
            self.stream
                .read_exact(&mut key)
                .map_err(|e| format!("WS mask read error: {e}"))?;
            Some(key)
        } else {
            None
        };

        let mut payload = vec![0u8; payload_len];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| format!("WS payload read error: {e}"))?;

        if let Some(m) = mask_key {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }

        if opcode == 0x8 {
            return Err("WebSocket connection closed by target".to_string());
        }

        String::from_utf8(payload).map_err(|e| format!("Invalid UTF-8 payload: {e}"))
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;

        let req = json!({
            "id": id,
            "method": method,
            "params": params
        });
        self.send_message(&req.to_string())?;

        // Read frames until response with matching id arrives
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            let msg = self.read_message()?;
            if let Ok(val) = serde_json::from_str::<Value>(&msg)
                && val.get("id").and_then(|v| v.as_u64()) == Some(id)
            {
                if let Some(err) = val.get("error") {
                    return Err(format!("CDP error: {}", err));
                }
                return val
                    .get("result")
                    .cloned()
                    .ok_or_else(|| "CDP response lacks result payload".to_string());
            }
        }
        Err(format!("CDP call '{method}' timed out waiting for id {id}"))
    }
}

fn resolve_ws_target(endpoint: &str, target_id: Option<&str>) -> Result<(String, Value), String> {
    let targets = fetch_cdp_targets(endpoint)?;
    let target = if let Some(id) = target_id {
        targets
            .iter()
            .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(id))
    } else {
        // Find first page target, or fallback to first target with webSocketDebuggerUrl
        targets
            .iter()
            .find(|t| t.get("type").and_then(|v| v.as_str()) == Some("page"))
            .or_else(|| {
                targets
                    .iter()
                    .find(|t| t.get("webSocketDebuggerUrl").is_some())
            })
    };

    match target {
        Some(t) => {
            let ws = t
                .get("webSocketDebuggerUrl")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Target lacks webSocketDebuggerUrl".to_string())?;
            Ok((ws.to_string(), t.clone()))
        }
        None => Err("No matching browser or Electron target found".to_string()),
    }
}

// Minimal RFC 4648 Base64 decoder
fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    const TABLE: [i8; 256] = {
        let mut t = [-1i8; 256];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i as i8;
            i += 1;
        }
        i = 0;
        while i < 26 {
            t[(b'a' + i) as usize] = (26 + i) as i8;
            i += 1;
        }
        i = 0;
        while i < 10 {
            t[(b'0' + i) as usize] = (52 + i) as i8;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };
    let clean: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut val = 0u32;
        for &b in chunk {
            let v = TABLE[b as usize];
            if v < 0 {
                return Err(format!("Invalid base64 byte: {}", b as char));
            }
            val = (val << 6) | (v as u32);
        }
        match chunk.len() {
            4 => {
                out.push((val >> 16) as u8);
                out.push((val >> 8) as u8);
                out.push(val as u8);
            }
            3 => {
                out.push((val >> 10) as u8);
                out.push((val >> 2) as u8);
            }
            2 => {
                out.push((val >> 2) as u8);
            }
            _ => return Err("Invalid base64 chunk".to_string()),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------
// CDP High-Level Operations
// ---------------------------------------------------------

pub fn capture_web_screenshot(args: &Value) -> Value {
    let endpoint = args
        .get("cdp_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("http://127.0.0.1:9222");
    let target_id = args.get("target_id").and_then(|v| v.as_str());
    let output_path = args
        .get("output_path")
        .or_else(|| args.get("output_file"))
        .and_then(|v| v.as_str());
    let format = args.get("format").and_then(|v| v.as_str()).unwrap_or("png");

    let (ws_url, target_info) = match resolve_ws_target(endpoint, target_id) {
        Ok(t) => t,
        Err(e) => return json!({ "status": "unavailable", "message": e }),
    };

    let mut session = match CdpSession::connect(&ws_url) {
        Ok(s) => s,
        Err(e) => {
            return json!({ "status": "error", "message": format!("Failed to connect to page WS: {e}") });
        }
    };

    let params = json!({
        "format": format,
        "fromSurface": true,
        "captureBeyondViewport": false
    });

    match session.call("Page.captureScreenshot", params) {
        Ok(res) => {
            let Some(b64) = res.get("data").and_then(Value::as_str) else {
                return json!({"status": "error", "message": "CDP screenshot response has no data"});
            };
            let raw_bytes = match decode_base64(b64) {
                Ok(bytes) if !bytes.is_empty() => bytes,
                Ok(_) => {
                    return json!({"status": "error", "message": "CDP screenshot is empty"});
                }
                Err(error) => {
                    return json!({"status": "error", "message": format!("Invalid screenshot base64: {error}")});
                }
            };
            let mut result = json!({
                "status": "complete",
                "target_id": target_info.get("id"),
                "target_title": target_info.get("title"),
                "target_url": target_info.get("url"),
                "media_type": format!("image/{format}"),
                "bytes": raw_bytes.len(),
            });

            if let Some(out) = output_path {
                let saved = (|| -> std::io::Result<()> {
                    use std::io::Write;
                    let mut file = fs::File::options().write(true).create_new(true).open(out)?;
                    file.write_all(&raw_bytes)?;
                    file.sync_all()
                })();
                if let Err(error) = saved {
                    return json!({
                        "status": "error",
                        "message": format!("Screenshot was not safely saved to {out}: {error}")
                    });
                }
                result["saved_path"] = json!(out);
            } else {
                result["data_base64_preview"] =
                    json!(if b64.len() > 120 { &b64[..120] } else { b64 });
            }
            result
        }
        Err(e) => json!({ "status": "error", "message": e }),
    }
}

pub fn evaluate_web_script(args: &Value) -> Value {
    let endpoint = args
        .get("cdp_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("http://127.0.0.1:9222");
    let target_id = args.get("target_id").and_then(|v| v.as_str());
    let expression = args
        .get("expression")
        .and_then(|v| v.as_str())
        .unwrap_or("window.location.href");

    let (ws_url, target_info) = match resolve_ws_target(endpoint, target_id) {
        Ok(t) => t,
        Err(e) => return json!({ "status": "unavailable", "message": e }),
    };

    let mut session = match CdpSession::connect(&ws_url) {
        Ok(s) => s,
        Err(e) => return json!({ "status": "error", "message": e }),
    };

    let params = json!({
        "expression": expression,
        "returnByValue": true,
        "awaitPromise": true
    });

    match session.call("Runtime.evaluate", params) {
        Ok(res) => {
            if let Some(exception) = res.get("exceptionDetails") {
                return json!({
                    "status": "error",
                    "message": "JavaScript evaluation raised an exception",
                    "exception": exception,
                    "expression": expression
                });
            }
            let Some(inner_res) = res.get("result") else {
                return json!({
                    "status": "error",
                    "message": "CDP Runtime.evaluate response has no result"
                });
            };
            json!({
                "status": "complete",
                "target_id": target_info.get("id"),
                "target_title": target_info.get("title"),
                "target_url": target_info.get("url"),
                "expression": expression,
                "result": inner_res.get("value").unwrap_or(inner_res),
                "type": inner_res.get("type"),
            })
        }
        Err(e) => json!({ "status": "error", "message": e }),
    }
}

pub fn inspect_web_page(args: &Value) -> Value {
    let endpoint = args
        .get("cdp_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("http://127.0.0.1:9222");
    let target_id = args.get("target_id").and_then(|v| v.as_str());

    let (ws_url, target_info) = match resolve_ws_target(endpoint, target_id) {
        Ok(t) => t,
        Err(e) => return json!({ "status": "unavailable", "message": e }),
    };

    let mut session = match CdpSession::connect(&ws_url) {
        Ok(s) => s,
        Err(e) => return json!({ "status": "error", "message": e }),
    };

    // Evaluate high-value page attributes
    let eval_code = "({
        title: document.title,
        url: window.location.href,
        userAgent: navigator.userAgent,
        html_length: document.documentElement ? document.documentElement.outerHTML.length : 0,
        scripts_count: document.scripts ? document.scripts.length : 0,
        links_count: document.links ? document.links.length : 0,
        scripts: Array.from(document.scripts || []).slice(0, 20).map(s => s.src || '<inline>')
    })";

    let page_meta = match session.call(
        "Runtime.evaluate",
        json!({
            "expression": eval_code,
            "returnByValue": true
        }),
    ) {
        Ok(response) => match response.get("result").and_then(|value| value.get("value")) {
            Some(metadata) => metadata.clone(),
            None => {
                return json!({
                    "status": "error",
                    "message": "CDP page inspection returned no observed page metadata"
                });
            }
        },
        Err(error) => return json!({"status": "error", "message": error}),
    };

    json!({
        "status": "complete",
        "endpoint": endpoint,
        "target_id": target_info.get("id"),
        "target_title": target_info.get("title"),
        "target_url": target_info.get("url"),
        "page_metadata": page_meta,
        "is_electron": target_info.get("url").and_then(|u| u.as_str()).map(|s| s.starts_with("file://")).unwrap_or(false)
    })
}

pub fn inspect_electron_page(args: &Value) -> Value {
    inspect_web_page(args)
}

fn unavailable_web_analysis(operation: &str) -> Value {
    json!({
        "status": "unavailable",
        "operation": operation,
        "reason": "This operation does not collect or compare the required CDP evidence"
    })
}

pub fn inspect_web_event_listeners(_args: &Value) -> Value {
    unavailable_web_analysis("inspect_web_event_listeners")
}

pub fn discover_webmcp_tools(_args: &Value) -> Value {
    unavailable_web_analysis("discover_webmcp_tools")
}

pub fn observe_web_session(_args: &Value) -> Value {
    unavailable_web_analysis("observe_web_session")
}

pub fn observe_web_execution(args: &Value) -> Value {
    // If expression provided, evaluate directly
    if args.get("expression").is_some() {
        evaluate_web_script(args)
    } else {
        unavailable_web_analysis("observe_web_execution")
    }
}

pub fn export_web_scripts(args: &Value) -> Value {
    let endpoint = args
        .get("cdp_endpoint")
        .and_then(|v| v.as_str())
        .unwrap_or("http://127.0.0.1:9222");
    let target_id = args.get("target_id").and_then(|v| v.as_str());
    let out_dir = args
        .get("output_directory")
        .and_then(|v| v.as_str())
        .unwrap_or("./exported_scripts");

    let (ws_url, _target_info) = match resolve_ws_target(endpoint, target_id) {
        Ok(t) => t,
        Err(e) => return json!({ "status": "unavailable", "message": e }),
    };

    let mut session = match CdpSession::connect(&ws_url) {
        Ok(s) => s,
        Err(e) => return json!({ "status": "error", "message": e }),
    };

    // Dump scripts via document.scripts evaluation
    let eval_code = "Array.from(document.scripts).map(s => ({ src: s.src, content: s.innerHTML }))";
    let scripts_data = match session.call(
        "Runtime.evaluate",
        json!({
            "expression": eval_code,
            "returnByValue": true
        }),
    ) {
        Ok(response) => match response.get("result").and_then(|value| value.get("value")) {
            Some(Value::Array(scripts)) => scripts.clone(),
            _ => {
                return json!({
                    "status": "error",
                    "message": "CDP did not provide a verified scripts array"
                });
            }
        },
        Err(error) => return json!({"status": "error", "message": error}),
    };

    if let Err(error) = fs::create_dir_all(out_dir) {
        return json!({"status": "error", "message": format!("Cannot create output directory: {error}")});
    }

    let mut exported = Vec::new();

    {
        for (i, item) in scripts_data.iter().enumerate() {
            let content = item.get("content").and_then(|v| v.as_str()).unwrap_or("");
            if !content.is_empty() {
                let file_path = Path::new(out_dir).join(format!("inline_script_{i}.js"));
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&file_path)
                {
                    Ok(mut file) => {
                        if let Err(error) = file.write_all(content.as_bytes()) {
                            return json!({"status": "error", "message": format!("Cannot write script: {error}")});
                        }
                        exported.push(file_path.to_string_lossy().to_string());
                    }
                    Err(error) => {
                        return json!({"status": "error", "message": format!("Cannot safely create script file: {error}")});
                    }
                }
            }
        }
    }

    json!({
        "status": "complete",
        "output_directory": out_dir,
        "exported_scripts_count": exported.len(),
        "scripts": exported
    })
}

pub fn trace_web_module_imports(_args: &Value) -> Value {
    unavailable_web_analysis("trace_web_module_imports")
}

pub fn trace_web_source_location(_args: &Value) -> Value {
    unavailable_web_analysis("trace_web_source_location")
}

pub fn compare_web_captures(_args: &Value) -> Value {
    unavailable_web_analysis("compare_web_captures")
}

pub fn compare_web_screenshots(_args: &Value) -> Value {
    unavailable_web_analysis("compare_web_screenshots")
}

pub fn analyze_web_bundle(_args: &Value) -> Value {
    unavailable_web_analysis("analyze_web_bundle")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdp_content_lengths_are_bounded_before_allocation() {
        assert_eq!(
            parse_cdp_content_length("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n").unwrap(),
            11
        );
        assert!(
            parse_cdp_content_length("HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n").is_err()
        );
        assert!(parse_cdp_content_length("Content-Length: 3\r\nContent-Length: 3").is_err());
        assert!(parse_cdp_content_length("Content-Length: nan").is_err());
        assert!(parse_cdp_content_length("HTTP/1.1 200 OK").is_err());
    }

    #[test]
    fn cdp_websocket_frame_lengths_are_bounded_before_allocation() {
        assert_eq!(checked_ws_payload_len(123).unwrap(), 123);
        assert!(checked_ws_payload_len(MAX_CDP_WS_FRAME_BYTES + 1).is_err());
        assert!(checked_ws_payload_len(u64::MAX).is_err());
    }

    #[test]
    fn rfc_6455_accept_challenge_matches_standard_example() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = websocket_accept_value(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        let headers = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        assert!(validate_websocket_handshake(&headers, &accept).is_ok());
        assert!(validate_websocket_handshake(&headers, "forged").is_err());
        assert!(validate_websocket_handshake("HTTP/1.1 101 Switching Protocols\r\n\r\n", &accept).is_err());
    }

    #[test]
    fn websocket_challenge_and_mask_are_os_random() {
        let mut key = [0u8; 16];
        let mut mask = [0u8; 4];
        secure_random_bytes(&mut key).unwrap();
        secure_random_bytes(&mut mask).unwrap();
        assert_eq!(encode_base64(&key).len(), 24);
        assert_eq!(mask.len(), 4);
    }

    #[test]
    fn unavailable_cdp_analyses_must_not_fabricate_evidence() {
        let args = json!({"selector": "*", "generated_position": {"line": 4}});
        for value in [
            inspect_web_event_listeners(&args),
            discover_webmcp_tools(&args),
            observe_web_session(&args),
            observe_web_execution(&args),
            trace_web_module_imports(&args),
            trace_web_source_location(&args),
            compare_web_captures(&args),
            compare_web_screenshots(&args),
            analyze_web_bundle(&args),
        ] {
            assert_eq!(value["status"], "unavailable");
            assert!(value.get("identical").is_none());
            assert!(value.get("events_captured").is_none());
            assert!(value.get("original_position").is_none());
        }
    }

    #[test]
    fn rejects_oversized_cdp_http_body_from_a_real_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            // Drain the client's GET first: closing with unread request data
            // can cause a TCP reset on Windows before the response arrives.
            let mut request = [0u8; 1024];
            let _ = std::io::Read::read(&mut peer, &mut request).unwrap();
            std::io::Write::write_all(
                &mut peer,
                b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n",
            )
            .unwrap();
        });
        let result = fetch_cdp_targets(&format!("http://{addr}"));
        let error = result.unwrap_err();
        assert!(
            error.contains("2 MiB limit"),
            "unexpected CDP response error: {error}"
        );
        server.join().unwrap();
    }

    #[test]
    fn rejects_huge_websocket_frame_header_from_a_real_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = std::io::Read::read(&mut peer, &mut request).unwrap();
            std::io::Write::write_all(
                &mut peer,
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            )
            .unwrap();
            std::io::Write::write_all(&mut peer, &[0x81, 0x7f]).unwrap();
            std::io::Write::write_all(&mut peer, &u64::MAX.to_be_bytes()).unwrap();
        });
        let mut session = CdpSession::connect(&format!("ws://{addr}/devtools/page/test")).unwrap();
        assert!(session.read_message().unwrap_err().contains("16 MiB limit"));
        server.join().unwrap();
    }

    #[test]
    fn test_cdp_list_offline() {
        let res = list_browser_targets(&json!({ "cdp_endpoint": "http://127.0.0.1:65432" }));
        assert_eq!(res.get("status").unwrap().as_str(), Some("unavailable"));
    }

    #[test]
    fn test_base64_decode() {
        let text = "SGVsbG8gV29ybGQ=";
        let decoded = decode_base64(text).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }

    #[test]
    fn test_ws_mask_unmask() {
        let msg = "test-cdp-payload";
        let mask = [0x12, 0x34, 0x56, 0x78];
        let mut masked = Vec::new();
        for (i, &b) in msg.as_bytes().iter().enumerate() {
            masked.push(b ^ mask[i % 4]);
        }
        for (i, b) in masked.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        assert_eq!(String::from_utf8(masked).unwrap(), msg);
    }
}
