use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

pub struct DebuggerSession {
    pub id: String,
    pub kind: String,
    stdin: Arc<Mutex<ChildStdin>>,
    output_log: Arc<Mutex<OutputLog>>,
    child: Arc<Mutex<Child>>,
}

const MAX_DEBUG_SESSIONS: usize = 8;
const MAX_DEBUG_LOG_LINES: usize = 512;
const MAX_DEBUG_LINE_BYTES: usize = 8192;

#[derive(Default)]
struct OutputLog {
    next_sequence: u64,
    records: VecDeque<(u64, String)>,
}

impl OutputLog {
    fn push(&mut self, message: String) {
        self.records.push_back((self.next_sequence, message));
        self.next_sequence = self.next_sequence.saturating_add(1);
        while self.records.len() > MAX_DEBUG_LOG_LINES {
            self.records.pop_front();
        }
    }

    fn since(&self, sequence: u64) -> Vec<String> {
        self.records
            .iter()
            .filter(|(number, _)| *number >= sequence)
            .map(|(_, line)| line.clone())
            .collect()
    }

    fn recent(&self, count: usize) -> Vec<String> {
        self.records.iter().rev().take(count).map(|(_, line)| line.clone()).collect()
    }
}

/// Drain arbitrary debugger stdout/stderr using bounded line buffers.
/// A client-controlled line can never occupy more than 8192 bytes in RAM.
fn collect_debug_output<R: Read>(
    stream: R,
    output: &Arc<Mutex<OutputLog>>,
    prefix: &str,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    let mut truncated = false;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            if !line.is_empty() || truncated {
                let mut text = format!("{prefix}{}", String::from_utf8_lossy(&line));
                if truncated {
                    text.push_str(" [truncated]");
                }
                output.lock().unwrap().push(text);
            }
            return Ok(());
        }
        let newline = buf.iter().position(|byte| *byte == b'\n');
        let len = newline.unwrap_or(buf.len());
        let amount = len.min(MAX_DEBUG_LINE_BYTES.saturating_sub(line.len()));
        line.extend_from_slice(&buf[..amount]);
        if amount < len {
            truncated = true;
        }
        reader.consume(len + usize::from(newline.is_some()));
        if newline.is_some() {
            let mut text = format!("{prefix}{}", String::from_utf8_lossy(&line));
            if truncated {
                text.push_str(" [truncated]");
            }
            output.lock().unwrap().push(text);
            line.clear();
            truncated = false;
        }
    }
}

fn gdb_result_status(lines: &[String]) -> &'static str {
    if lines.iter().any(|line| line.contains("^error")) {
        "error"
    } else if lines.iter().any(|line| line.contains("^done")) {
        "complete"
    } else {
        "unverified"
    }
}

static SESSIONS: OnceLock<RwLock<HashMap<String, DebuggerSession>>> = OnceLock::new();

fn get_sessions() -> &'static RwLock<HashMap<String, DebuggerSession>> {
    SESSIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn spawn_session(id: String, kind: &str, cmd: &str, args: &[&str]) -> Result<String, String> {
    let mut sessions = get_sessions().write().unwrap();
    if sessions.len() >= MAX_DEBUG_SESSIONS {
        return Err(format!("Debugger session limit reached ({MAX_DEBUG_SESSIONS})"));
    }
    if sessions.contains_key(&id) {
        return Err("Debugger session ID already exists".to_string());
    }
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn {cmd}: {e}"))?;

    let stdin = child.stdin.take().ok_or("Failed to capture stdin")?;
    let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
    let stderr = child.stderr.take().ok_or("Failed to capture stderr")?;

    let output_log = Arc::new(Mutex::new(OutputLog::default()));
    let stdout_log = Arc::clone(&output_log);
    let stderr_log = Arc::clone(&output_log);
    thread::spawn(move || {
        let _ = collect_debug_output(stdout, &stdout_log, "");
    });
    thread::spawn(move || {
        let _ = collect_debug_output(stderr, &stderr_log, "[stderr] ");
    });

    let session = DebuggerSession {
        id: id.clone(),
        kind: kind.to_string(),
        stdin: Arc::new(Mutex::new(stdin)),
        output_log,
        child: Arc::new(Mutex::new(child)),
    };

    sessions.insert(id.clone(), session);
    Ok(id)
}

pub fn start_gdb_session(args: &Value) -> Value {
    let session_id = format!("gdb_{}", uuid_simple());
    let tty = args.get("inferior_tty").and_then(|v| v.as_str());

    let mut cmd_args = vec!["--interpreter=mi3", "-q"];
    if let Some(t) = tty {
        cmd_args.push("-tty");
        cmd_args.push(t);
    }

    match spawn_session(session_id.clone(), "gdb", "gdb", &cmd_args) {
        Ok(id) => json!({
            "status": "active",
            "session_id": id,
            "kind": "gdb",
            "mi_version": 3
        }),
        Err(e) => json!({ "status": "error", "message": e }),
    }
}

pub fn gdb_console(args: &Value) -> Value {
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return json!({ "status": "error", "message": "Missing session_id" }),
    };
    let command = match args.get("command").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return json!({ "status": "error", "message": "Missing command" }),
    };

    let sessions = get_sessions().read().unwrap();
    let session = match sessions.get(session_id) {
        Some(s) => s,
        None => {
            return json!({ "status": "error", "message": format!("Session {session_id} not found") });
        }
    };

    let start_idx = {
        let log = session.output_log.lock().unwrap();
        log.next_sequence
    };

    {
        let mut stdin = session.stdin.lock().unwrap();
        if let Err(e) = writeln!(stdin, "{command}") {
            return json!({ "status": "error", "message": format!("Failed to send command: {e}") });
        }
        let _ = stdin.flush();
    }

    let start_time = Instant::now();
    let mut collected = Vec::new();
    while start_time.elapsed() < Duration::from_millis(1500) {
        thread::sleep(Duration::from_millis(50));
        let log = session.output_log.lock().unwrap();
        if log.next_sequence > start_idx {
            collected = log.since(start_idx);
            if gdb_result_status(&collected) != "unverified" {
                break;
            }
        }
    }

    let status = gdb_result_status(&collected);
    json!({
        "status": status,
        "session_id": session_id,
        "response_verified": status == "complete",
        "records": collected
    })
}

pub fn gdb_session_status(args: &Value) -> Value {
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return json!({ "status": "error", "message": "Missing session_id" }),
    };

    let sessions = get_sessions().read().unwrap();
    if let Some(s) = sessions.get(session_id) {
        let log = s.output_log.lock().unwrap();
        json!({
            "status": "active",
            "session_id": session_id,
            "recent_records": log.recent(20)
        })
    } else {
        json!({ "status": "closed", "session_id": session_id })
    }
}

pub fn close_gdb_session(args: &Value) -> Value {
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return json!({ "status": "error", "message": "Missing session_id" }),
    };

    let mut sessions = get_sessions().write().unwrap();
    if let Some(session) = sessions.remove(session_id) {
        if let Ok(mut stdin) = session.stdin.lock() {
            let _ = writeln!(stdin, "-gdb-exit");
            let _ = stdin.flush();
        }
        if let Ok(mut child) = session.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        json!({ "status": "closed", "session_id": session_id })
    } else {
        json!({ "status": "error", "message": format!("Session {session_id} not found") })
    }
}

// ---------------------------------------------------------
// Rizin Debug Session
// ---------------------------------------------------------

pub fn start_rizin_debug_session(args: &Value) -> Value {
    let session_id = format!("rz_{}", uuid_simple());
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");

    match spawn_session(session_id.clone(), "rizin", "rizin", &["-q", "-d", path]) {
        Ok(id) => json!({
            "status": "active",
            "session_id": id,
            "kind": "rizin"
        }),
        Err(e) => json!({ "status": "error", "message": e }),
    }
}

pub fn rizin_debug_command(args: &Value) -> Value {
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return json!({ "status": "error", "message": "Missing session_id" }),
    };
    let command = match args.get("command").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return json!({ "status": "error", "message": "Missing command" }),
    };

    let sessions = get_sessions().read().unwrap();
    let session = match sessions.get(session_id) {
        Some(s) => s,
        None => {
            return json!({ "status": "error", "message": format!("Session {session_id} not found") });
        }
    };

    let start_idx = {
        let log = session.output_log.lock().unwrap();
        log.next_sequence
    };

    {
        let mut stdin = session.stdin.lock().unwrap();
        let _ = writeln!(stdin, "{command}");
        let _ = stdin.flush();
    }

    thread::sleep(Duration::from_millis(200));
    let log = session.output_log.lock().unwrap();
    let collected = log.since(start_idx);
    json!({
        "status": "unverified",
        "session_id": session_id,
        "response_verified": false,
        "output": collected.join("\n"),
        "reason": "No Rizin command-completion protocol was observed"
    })
}

pub fn rizin_debug_session_status(args: &Value) -> Value {
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return json!({ "status": "error", "message": "Missing session_id" }),
    };

    let sessions = get_sessions().read().unwrap();
    if let Some(s) = sessions.get(session_id) {
        let log = s.output_log.lock().unwrap();
        json!({
            "status": "active",
            "session_id": session_id,
            "recent_output": log.recent(10)
        })
    } else {
        json!({ "status": "closed", "session_id": session_id })
    }
}

pub fn close_rizin_debug_session(args: &Value) -> Value {
    let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return json!({ "status": "error", "message": "Missing session_id" }),
    };

    let mut sessions = get_sessions().write().unwrap();
    if let Some(session) = sessions.remove(session_id) {
        if let Ok(mut child) = session.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        json!({ "status": "closed", "session_id": session_id })
    } else {
        json!({ "status": "error", "message": format!("Session {session_id} not found") })
    }
}

// ---------------------------------------------------------
// Frida Persistent Session
// ---------------------------------------------------------

fn unavailable_frida_operation(operation: &str) -> Value {
    json!({
        "status": "unavailable",
        "operation": operation,
        "reason": "No Frida process, transport, or instrumentation session is connected"
    })
}

pub fn start_frida_session(_args: &Value) -> Value {
    unavailable_frida_operation("start_frida_session")
}

pub fn frida_session_status(_args: &Value) -> Value {
    unavailable_frida_operation("frida_session_status")
}

pub fn load_frida_script(_args: &Value) -> Value {
    unavailable_frida_operation("load_frida_script")
}

pub fn unload_frida_script(_args: &Value) -> Value {
    unavailable_frida_operation("unload_frida_script")
}

pub fn resume_frida_session(_args: &Value) -> Value {
    unavailable_frida_operation("resume_frida_session")
}

pub fn close_frida_session(_args: &Value) -> Value {
    unavailable_frida_operation("close_frida_session")
}

fn uuid_simple() -> String {
    use std::time::SystemTime;
    let n = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{n:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debugger_log_is_bounded_and_sequences_do_not_reuse() {
        let mut log = OutputLog::default();
        for i in 0..(MAX_DEBUG_LOG_LINES + 25) {
            log.push(format!("record-{i}"));
        }
        assert_eq!(log.records.len(), MAX_DEBUG_LOG_LINES);
        assert_eq!(log.next_sequence, (MAX_DEBUG_LOG_LINES + 25) as u64);
        assert_eq!(log.since(log.next_sequence), Vec::<String>::new());
        assert_eq!(log.recent(1), vec![format!("record-{}", MAX_DEBUG_LOG_LINES + 24)]);
    }

    #[test]
    fn debugger_stdout_truncates_long_lines_and_retains_next_line() {
        let log = Arc::new(Mutex::new(OutputLog::default()));
        let mut input = vec![b'X'; MAX_DEBUG_LINE_BYTES * 4];
        input.extend_from_slice(b"\nok\n");
        collect_debug_output(&input[..], &log, "").unwrap();
        let output = log.lock().unwrap();
        assert_eq!(output.records.len(), 2);
        assert!(output.records[0].1.ends_with("[truncated]"));
        assert!(output.records[0].1.len() <= MAX_DEBUG_LINE_BYTES + 16);
        assert_eq!(output.records[1].1, "ok");
    }

    #[test]
    fn debugger_completion_requires_protocol_evidence() {
        assert_eq!(gdb_result_status(&[]), "unverified");
        assert_eq!(gdb_result_status(&["(gdb)".into()]), "unverified");
        assert_eq!(gdb_result_status(&["12^done".into()]), "complete");
        assert_eq!(gdb_result_status(&["12^error,msg=failed".into()]), "error");
    }

    #[test]
    fn frida_stub_operations_must_not_fabricate_sessions() {
        let args = json!({"session_id": "fake", "mode": "attach", "script": "send('hi')"});
        for output in [
            start_frida_session(&args),
            frida_session_status(&args),
            load_frida_script(&args),
            unload_frida_script(&args),
            resume_frida_session(&args),
            close_frida_session(&args),
        ] {
            assert_eq!(output["status"], "unavailable");
            assert!(output.get("session_id").is_none());
            assert!(output.get("script_id").is_none());
            assert!(output.get("loaded").is_none());
        }
    }
}
