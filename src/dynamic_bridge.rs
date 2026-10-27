use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdpTarget {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(rename = "type", default)]
    pub target_type: String,
    #[serde(default)]
    pub url: String,
    #[serde(rename = "webSocketDebuggerUrl", default)]
    pub web_socket_debugger_url: Option<String>,
    #[serde(rename = "devtoolsFrontendUrl", default)]
    pub devtools_frontend_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdbDevice {
    pub serial: String,
    pub state: String,
    pub product: Option<String>,
    pub model: Option<String>,
    pub device: Option<String>,
    pub transport_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdbDeviceProps {
    pub serial: String,
    pub android_version: Option<String>,
    pub sdk_version: Option<String>,
    pub model: Option<String>,
    pub manufacturer: Option<String>,
    pub cpu_abi: Option<String>,
    pub build_fingerprint: Option<String>,
    pub is_emulator: bool,
    pub raw_properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveProcessSummary {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveProcessDetail {
    pub pid: u32,
    pub name: String,
    pub cmdline: Vec<String>,
    pub exe_path: Option<String>,
    pub state: Option<String>,
    pub ppid: Option<u32>,
    pub threads: Option<u32>,
    pub memory_vmsize_kb: Option<u64>,
    pub memory_vmrss_kb: Option<u64>,
    pub mapped_libraries: Vec<String>,
}

pub struct DynamicBridge;

impl DynamicBridge {
    // ==========================================
    // Chrome DevTools Protocol (CDP) Bridge
    // ==========================================

    /// Query loopback Chrome/Electron CDP endpoint (e.g. "http://127.0.0.1:9222" or "127.0.0.1:9222")
    pub fn query_cdp_targets(endpoint: &str) -> Result<Vec<CdpTarget>, Box<dyn Error>> {
        // One bounded parser for both MCP discovery and direct CDP inspection.
        // The old implementation trusted Content-Length and allocated without
        // a cap; never reintroduce a second unbounded HTTP reader.
        let values = crate::cdp::fetch_cdp_targets(endpoint)?;
        let targets: Vec<CdpTarget> = serde_json::from_value(Value::Array(values))?;
        Ok(targets)
    }

    /// List only Electron file:// or app pages from CDP endpoint
    pub fn list_electron_targets(endpoint: &str) -> Result<Vec<CdpTarget>, Box<dyn Error>> {
        let all = Self::query_cdp_targets(endpoint)?;
        let filtered: Vec<CdpTarget> = all
            .into_iter()
            .filter(|t| {
                t.url.starts_with("file://")
                    || t.target_type == "page"
                    || t.target_type == "webview"
            })
            .collect();
        Ok(filtered)
    }

    // ==========================================
    // Android Debug Bridge (ADB) Integration
    // ==========================================

    /// List connected Android devices via `adb devices -l`
    pub fn list_adb_devices() -> Result<Vec<AdbDevice>, Box<dyn Error>> {
        let output = Command::new("adb").args(["devices", "-l"]).output()?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!("adb failed: {}", err).into());
        }

        let text = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_adb_devices_output(&text))
    }

    pub fn parse_adb_devices_output(output: &str) -> Vec<AdbDevice> {
        let mut devices = Vec::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("List of devices") || line.starts_with('*') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let serial = parts[0].to_string();
                let state = parts[1].to_string();

                let mut product = None;
                let mut model = None;
                let mut device = None;
                let mut transport_id = None;

                for token in &parts[2..] {
                    if let Some(val) = token.strip_prefix("product:") {
                        product = Some(val.to_string());
                    } else if let Some(val) = token.strip_prefix("model:") {
                        model = Some(val.to_string());
                    } else if let Some(val) = token.strip_prefix("device:") {
                        device = Some(val.to_string());
                    } else if let Some(val) = token.strip_prefix("transport_id:") {
                        transport_id = Some(val.to_string());
                    }
                }

                devices.push(AdbDevice {
                    serial,
                    state,
                    product,
                    model,
                    device,
                    transport_id,
                });
            }
        }
        devices
    }

    /// Read system properties from device via `adb shell getprop`
    pub fn inspect_adb_device(serial: Option<&str>) -> Result<AdbDeviceProps, Box<dyn Error>> {
        let mut cmd = Command::new("adb");
        if let Some(s) = serial {
            cmd.args(["-s", s]);
        }
        cmd.args(["shell", "getprop"]);

        let output = cmd.output()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let props = Self::parse_getprop_output(&text);

        let android_version = props.get("ro.build.version.release").cloned();
        let sdk_version = props.get("ro.build.version.sdk").cloned();
        let model = props.get("ro.product.model").cloned();
        let manufacturer = props.get("ro.product.manufacturer").cloned();
        let cpu_abi = props.get("ro.product.cpu.abi").cloned();
        let build_fingerprint = props.get("ro.build.fingerprint").cloned();

        let is_emulator = props
            .get("ro.kernel.qemu")
            .map(|v| v == "1")
            .unwrap_or_else(|| {
                model
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains("emulator")
                    || model
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains("sdk")
            });

        Ok(AdbDeviceProps {
            serial: serial.unwrap_or("default").to_string(),
            android_version,
            sdk_version,
            model,
            manufacturer,
            cpu_abi,
            build_fingerprint,
            is_emulator,
            raw_properties: props,
        })
    }

    pub fn parse_getprop_output(output: &str) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for line in output.lines() {
            let line = line.trim();
            if line.starts_with('[')
                && line.contains("]: [")
                && let Some(split) = line.find("]: [")
            {
                let key = &line[1..split];
                let val = line[split + 4..].trim_end_matches(']');
                map.insert(key.to_string(), val.to_string());
            }
        }
        map
    }

    /// List installed packages on device via `adb shell pm list packages`
    pub fn list_adb_packages(
        serial: Option<&str>,
        third_party_only: bool,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let mut cmd = Command::new("adb");
        if let Some(s) = serial {
            cmd.args(["-s", s]);
        }
        cmd.arg("shell").arg("pm").arg("list").arg("packages");
        if third_party_only {
            cmd.arg("-3");
        }

        let output = cmd.output()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let mut pkgs = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(pkg) = line.strip_prefix("package:") {
                pkgs.push(pkg.to_string());
            }
        }
        pkgs.sort();
        Ok(pkgs)
    }

    // ==========================================
    // Live Process & Memory Inspector (/proc)
    // ==========================================

    /// List live processes on host system
    pub fn list_live_processes(
        filter: Option<&str>,
    ) -> Result<Vec<LiveProcessSummary>, Box<dyn Error>> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Ok(pid) = name_str.parse::<u32>() {
                        let proc_path = entry.path();
                        let cmdline = fs::read(proc_path.join("cmdline"))
                            .map(|b| {
                                b.split(|&c| c == 0)
                                    .filter(|s| !s.is_empty())
                                    .map(|s| String::from_utf8_lossy(s).to_string())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();

                        let comm = fs::read_to_string(proc_path.join("comm"))
                            .map(|s| s.trim().to_string())
                            .unwrap_or_else(|_| name_str.to_string());

                        if let Some(f) = filter
                            && !comm.to_lowercase().contains(&f.to_lowercase())
                            && !cmdline.to_lowercase().contains(&f.to_lowercase())
                        {
                            continue;
                        }

                        results.push(LiveProcessSummary {
                            pid,
                            name: comm,
                            cmdline,
                        });
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let output = Command::new("ps").args(["-e", "-o", "pid,comm"]).output()?;
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && let Ok(pid) = parts[0].parse::<u32>()
                {
                    let comm = parts[1].to_string();
                    if let Some(f) = filter
                        && !comm.to_lowercase().contains(&f.to_lowercase())
                    {
                        continue;
                    }
                    results.push(LiveProcessSummary {
                        pid,
                        name: comm.clone(),
                        cmdline: comm,
                    });
                }
            }
        }

        results.sort_by_key(|p| p.pid);
        Ok(results)
    }

    /// Inspect detailed process state, file descriptor count, memory, and loaded dynamic libraries
    pub fn inspect_live_process(pid: u32) -> Result<LiveProcessDetail, Box<dyn Error>> {
        #[cfg(target_os = "linux")]
        {
            let proc_dir = format!("/proc/{}", pid);
            let proc_path = Path::new(&proc_dir);
            if !proc_path.exists() {
                return Err(format!("Process {} not found", pid).into());
            }

            let name = fs::read_to_string(proc_path.join("comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| format!("pid_{}", pid));

            let cmdline: Vec<String> = fs::read(proc_path.join("cmdline"))
                .map(|b| {
                    b.split(|&c| c == 0)
                        .filter(|s| !s.is_empty())
                        .map(|s| String::from_utf8_lossy(s).to_string())
                        .collect()
                })
                .unwrap_or_default();

            let exe_path = fs::read_link(proc_path.join("exe"))
                .ok()
                .map(|p| p.to_string_lossy().to_string());

            let mut state = None;
            let mut ppid = None;
            let mut threads = None;
            let mut memory_vmsize_kb = None;
            let mut memory_vmrss_kb = None;

            if let Ok(status) = fs::read_to_string(proc_path.join("status")) {
                for line in status.lines() {
                    let parts: Vec<&str> = line.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        let k = parts[0].trim();
                        let v = parts[1].trim();
                        match k {
                            "State" => state = Some(v.to_string()),
                            "PPid" => ppid = v.parse::<u32>().ok(),
                            "Threads" => threads = v.parse::<u32>().ok(),
                            "VmSize" => {
                                memory_vmsize_kb = v
                                    .split_whitespace()
                                    .next()
                                    .and_then(|n| n.parse::<u64>().ok());
                            }
                            "VmRSS" => {
                                memory_vmrss_kb = v
                                    .split_whitespace()
                                    .next()
                                    .and_then(|n| n.parse::<u64>().ok());
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Extract mapped dynamic libraries from /proc/{pid}/maps
            let mut mapped_libraries = Vec::new();
            if let Ok(maps) = fs::read_to_string(proc_path.join("maps")) {
                for line in maps.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let path = parts[5];
                        if (path.ends_with(".so") || path.contains(".so."))
                            && !mapped_libraries.contains(&path.to_string())
                        {
                            mapped_libraries.push(path.to_string());
                        }
                    }
                }
            }

            Ok(LiveProcessDetail {
                pid,
                name,
                cmdline,
                exe_path,
                state,
                ppid,
                threads,
                memory_vmsize_kb,
                memory_vmrss_kb,
                mapped_libraries,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(LiveProcessDetail {
                pid,
                name: format!("pid_{}", pid),
                cmdline: Vec::new(),
                exe_path: None,
                state: Some("active".to_string()),
                ppid: None,
                threads: None,
                memory_vmsize_kb: None,
                memory_vmrss_kb: None,
                mapped_libraries: Vec::new(),
            })
        }
    }

    // ==========================================
    // Optional External CLI Bridges
    // ==========================================

    pub fn find_in_path(bin: &str) -> Option<PathBuf> {
        #[cfg(windows)]
        let mut names = vec![bin.to_string()];
        #[cfg(not(windows))]
        let names = [bin.to_string()];
        // Unlike Unix, Windows PATH lookups use PATHEXT. Without this, native
        // executables such as cmd.exe, adb.exe and gdb.exe are falsely reported
        // as unavailable when callers supply their ordinary extensionless names.
        #[cfg(windows)]
        if PathBuf::from(bin).extension().is_none() {
            let extensions = env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
            for ext in extensions.split(';').filter(|ext| !ext.is_empty()) {
                let ext = if ext.starts_with('.') {
                    ext.to_string()
                } else {
                    format!(".{ext}")
                };
                names.push(format!("{bin}{ext}"));
            }
        }
        env::var_os("PATH").and_then(|paths| {
            env::split_paths(&paths).find_map(|directory| {
                names
                    .iter()
                    .map(|name| directory.join(name))
                    .find(|p| p.is_file())
            })
        })
    }

    pub fn run_optional_bridge(
        bin: &str,
        install_hint: &str,
        args: &[&str],
        timeout_secs: u64,
    ) -> Value {
        let bin_path = match Self::find_in_path(bin) {
            Some(p) => p,
            None => {
                return json!({
                    "status": "unavailable",
                    "tool": bin,
                    "install_hint": install_hint
                });
            }
        };

        let mut child = match Command::new(&bin_path)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return json!({
                    "status": "error",
                    "tool": bin,
                    "error": e.to_string()
                });
            }
        };

        let mut stdout_handle = child.stdout.take();
        let mut stderr_handle = child.stderr.take();

        let stdout_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut stream) = stdout_handle.take() {
                let _ = stream.read_to_end(&mut buf);
            }
            buf
        });

        let stderr_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut stream) = stderr_handle.take() {
                let _ = stream.read_to_end(&mut buf);
            }
            buf
        });

        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let mut timed_out = false;

        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Ok(s),
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        timed_out = true;
                        break child.wait();
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => break Err(e),
            }
        };

        let stdout_bytes = stdout_thread.join().unwrap_or_default();
        let stderr_bytes = stderr_thread.join().unwrap_or_default();

        let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
        let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();

        if timed_out {
            return json!({
                "status": "timeout",
                "tool": bin,
                "timeout_secs": timeout_secs,
                "stdout": stdout,
                "stderr": stderr
            });
        }

        match status {
            Ok(exit_status) => json!({
                "status": "ok",
                "tool": bin,
                "exit_code": exit_status.code(),
                "stdout": stdout,
                "stderr": stderr
            }),
            Err(e) => json!({
                "status": "error",
                "tool": bin,
                "error": e.to_string(),
                "stdout": stdout,
                "stderr": stderr
            }),
        }
    }

    pub fn run_gdb(args: &[&str]) -> Value {
        Self::run_optional_bridge("gdb", "apt install gdb || brew install gdb", args, 10)
    }

    pub fn run_frida(args: &[&str]) -> Value {
        Self::run_optional_bridge("frida", "pip install frida-tools", args, 10)
    }

    pub fn run_objdump(args: &[&str]) -> Value {
        Self::run_optional_bridge(
            "objdump",
            "apt install binutils || brew install binutils",
            args,
            10,
        )
    }

    pub fn run_rizin(args: &[&str]) -> Value {
        Self::run_optional_bridge(
            "rizin",
            "apt install rizin || https://github.com/rizinorg/rizin",
            args,
            10,
        )
    }

    pub fn run_sigrok(args: &[&str]) -> Value {
        Self::run_optional_bridge("sigrok-cli", "apt install sigrok-cli", args, 10)
    }

    pub fn run_jadx_or_apktool(args: &[&str]) -> Value {
        if Self::find_in_path("jadx").is_some() {
            Self::run_optional_bridge("jadx", "apt install jadx || brew install jadx", args, 30)
        } else {
            Self::run_optional_bridge(
                "apktool",
                "apt install apktool || brew install apktool",
                args,
                30,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_adb_devices() {
        let sample = "List of devices attached\nemulator-5554\tdevice product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1\n192.168.1.50:5555\tunauthorized transport_id:2\n";
        let devs = DynamicBridge::parse_adb_devices_output(sample);
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].serial, "emulator-5554");
        assert_eq!(devs[0].state, "device");
        assert_eq!(devs[0].model.as_deref(), Some("sdk_gphone64_arm64"));
        assert_eq!(devs[1].serial, "192.168.1.50:5555");
        assert_eq!(devs[1].state, "unauthorized");
    }

    #[test]
    fn test_parse_getprop() {
        let sample = "[ro.build.version.release]: [14]\n[ro.product.model]: [Pixel 7]\n[ro.build.version.sdk]: [34]\n";
        let map = DynamicBridge::parse_getprop_output(sample);
        assert_eq!(map.get("ro.build.version.release").unwrap(), "14");
        assert_eq!(map.get("ro.product.model").unwrap(), "Pixel 7");
        assert_eq!(map.get("ro.build.version.sdk").unwrap(), "34");
    }

    #[test]
    fn test_host_port_parser() {
        let (h, p) = DynamicBridge::parse_host_port("http://127.0.0.1:9222").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 9222);

        let (h2, p2) = DynamicBridge::parse_host_port("localhost:8080/").unwrap();
        assert_eq!(h2, "localhost");
        assert_eq!(p2, 8080);
    }

    #[test]
    fn test_optional_bridge_unavailable() {
        let res = DynamicBridge::run_optional_bridge(
            "definitely_non_existent_binary_xyz123",
            "hint",
            &[],
            1,
        );
        assert_eq!(res["status"], "unavailable");
        assert_eq!(res["tool"], "definitely_non_existent_binary_xyz123");
        assert_eq!(res["install_hint"], "hint");
    }

    #[test]
    fn test_optional_bridge_execution() {
        let (command, arguments): (&str, &[&str]) = if cfg!(windows) {
            ("cmd", &["/C", "echo hello_bridge"])
        } else {
            ("sh", &["-c", "echo hello_bridge"])
        };
        let res = DynamicBridge::run_optional_bridge(command, "none", arguments, 5);
        assert_eq!(res["status"], "ok");
        assert_eq!(res["exit_code"], 0);
        assert!(res["stdout"].as_str().unwrap().contains("hello_bridge"));
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_pathext_resolves_cmd() {
        let path = DynamicBridge::find_in_path("cmd").expect("cmd.exe should be on Windows PATH");
        assert!(path.is_file());
        assert!(
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        );
    }
}
