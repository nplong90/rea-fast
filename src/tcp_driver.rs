use serde_json::{json, Value};
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Check if a local TCP endpoint is active with a strict timeout (default 20ms).
pub fn probe_endpoint(addr: &str, timeout_ms: u64) -> bool {
    let socket_addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)).is_ok()
}

/// Send a raw HTTP POST request to a local JSON-RPC / MCP server (e.g. JEB on 127.0.0.1:8425)
pub fn send_raw_http_post(addr: &str, path: &str, body: &Value, timeout_ms: u64) -> Result<Value, String> {
    let socket_addr: SocketAddr = addr.parse().map_err(|e| format!("Invalid socket address {addr}: {e}"))?;
    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms))
        .map_err(|e| format!("Connection to {addr} failed: {e}"))?;

    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms * 4)))
        .map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms * 2)))
        .map_err(|e| e.to_string())?;

    let body_bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path, addr, body_bytes.len()
    );

    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(&body_bytes).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    let max_read = 16 * 1024 * 1024; // 16 MiB guard against unbounded OOM
    stream.take(max_read).read_to_end(&mut response)
        .map_err(|e| format!("Read error from {addr}: {e}"))?;

    if let Some(pos) = response.windows(4).position(|w| w == b"\r\n\r\n") {
        let body_slice = &response[pos + 4..];
        let mut json_val: Value = serde_json::from_slice(body_slice)
            .map_err(|e| format!("Invalid JSON response: {e}"))?;
        if let Some(res) = json_val.get_mut("result") {
            Ok(std::mem::take(res))
        } else {
            Ok(json_val)
        }
    } else {
        Err("Malformed HTTP response".to_string())
    }
}

/// Forward an MCP tool invocation to a local JEB MCP client if active (port 8425).
pub fn call_jeb_mcp(tool_name: &str, arguments: &Value) -> Value {
    let addr = "127.0.0.1:8425";
    if !probe_endpoint(addr, 25) {
        return unavailable_engine_response(
            "JEB Decompiler MCP Server",
            tool_name,
            "REA_JEB_MCP_URL not responding on 127.0.0.1:8425. Start JEB with MCP plugin enabled.",
            "inspect_android_package or decompile_apktool_jadx",
        );
    }

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    });

    match send_raw_http_post(addr, "/mcp", &payload, 1500) {
        Ok(res) => res,
        Err(err) => json!({
            "status": "error",
            "engine": "JEB",
            "message": err
        }),
    }
}

/// Standardized structured diagnostic response when a proprietary reverse engineering engine is offline.
pub fn unavailable_engine_response(
    engine: &str,
    tool_name: &str,
    install_hint: &str,
    recommended_fallback: &str,
) -> Value {
    json!({
        "status": "unavailable",
        "tool": tool_name,
        "engine": engine,
        "installed": false,
        "message": format!("{engine} is required for tool '{tool_name}' but is not responding or installed locally."),
        "install_hint": install_hint,
        "recommended_fallback": recommended_fallback,
        "rea_fast_native_alternative": recommended_fallback
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_inactive_port() {
        // Port 59199 is typically unused, connect timeout should quickly return false within 50ms
        let is_up = probe_endpoint("127.0.0.1:59199", 20);
        assert!(!is_up);
    }

    #[test]
    fn test_unavailable_response_format() {
        let resp = unavailable_engine_response("Ghidra", "analyze_function", "Install Ghidra headless", "inspect_binary_layout");
        assert_eq!(resp.get("status").and_then(|s| s.as_str()), Some("unavailable"));
        assert_eq!(resp.get("engine").and_then(|s| s.as_str()), Some("Ghidra"));
        assert!(resp.get("recommended_fallback").is_some());
    }
}
