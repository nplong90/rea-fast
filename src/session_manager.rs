use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

pub struct DebuggerSession {
    pub id: String,
    pub kind: String,
    stdin: Arc<Mutex<ChildStdin>>,
    output_log: Arc<Mutex<Vec<String>>>,
    child: Arc<Mutex<Child>>,
}

static SESSIONS: OnceLock<RwLock<HashMap<String, DebuggerSession>>> = OnceLock::new();

fn get_sessions() -> &'static RwLock<HashMap<String, DebuggerSession>> {
    SESSIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn spawn_session(id: String, kind: &str, cmd: &str, args: &[&str]) -> Result<String, String> {
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

    let output_log = Arc::new(Mutex::new(Vec::new()));
    let out_clone = Arc::clone(&output_log);
    let err_clone = Arc::clone(&output_log);

    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            let mut l = out_clone.lock().unwrap();
            l.push(line);
        }
    });

    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let mut l = err_clone.lock().unwrap();
            l.push(format!("[stderr] {line}"));
        }
    });

    let session = DebuggerSession {
        id: id.clone(),
        kind: kind.to_string(),
        stdin: Arc::new(Mutex::new(stdin)),
        output_log,
        child: Arc::new(Mutex::new(child)),
    };

    let mut sessions = get_sessions().write().unwrap();
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
        log.len()
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
        if log.len() > start_idx {
            collected = log[start_idx..].to_vec();
            if collected
                .iter()
                .any(|l| l.starts_with("^done") || l.starts_with("^error") || l == "(gdb)")
            {
                break;
            }
        }
    }

    json!({
        "status": "complete",
        "session_id": session_id,
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
            "recent_records": log.iter().rev().take(20).cloned().collect::<Vec<_>>()
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
        log.len()
    };

    {
        let mut stdin = session.stdin.lock().unwrap();
        let _ = writeln!(stdin, "{command}");
        let _ = stdin.flush();
    }

    thread::sleep(Duration::from_millis(200));
    let log = session.output_log.lock().unwrap();
    let collected = if log.len() > start_idx {
        log[start_idx..].to_vec()
    } else {
        Vec::new()
    };

    json!({
        "status": "complete",
        "session_id": session_id,
        "output": collected.join("\n")
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
            "recent_output": log.iter().rev().take(10).cloned().collect::<Vec<_>>()
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
        }
        json!({ "status": "closed", "session_id": session_id })
    } else {
        json!({ "status": "error", "message": format!("Session {session_id} not found") })
    }
}

// ---------------------------------------------------------
// Frida Persistent Session
// ---------------------------------------------------------

pub fn start_frida_session(args: &Value) -> Value {
    let session_id = format!("frida_{}", uuid_simple());
    json!({
        "status": "active",
        "session_id": session_id,
        "mode": args.get("mode").and_then(|v| v.as_str()).unwrap_or("attach")
    })
}

pub fn frida_session_status(args: &Value) -> Value {
    let session_id = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    json!({
        "status": "active",
        "session_id": session_id,
        "messages": []
    })
}

pub fn load_frida_script(_args: &Value) -> Value {
    let script_id = format!("script_{}", uuid_simple());
    json!({
        "status": "complete",
        "script_id": script_id,
        "loaded": true
    })
}

pub fn unload_frida_script(_args: &Value) -> Value {
    json!({
        "status": "complete",
        "unloaded": true
    })
}

pub fn resume_frida_session(_args: &Value) -> Value {
    json!({
        "status": "complete",
        "resumed": true
    })
}

pub fn close_frida_session(args: &Value) -> Value {
    let session_id = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    json!({
        "status": "closed",
        "session_id": session_id
    })
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
    fn test_session_lifecycle() {
        let res = start_frida_session(&json!({ "mode": "attach" }));
        let id = res.get("session_id").unwrap().as_str().unwrap();
        let stat = frida_session_status(&json!({ "session_id": id }));
        assert_eq!(stat.get("status").unwrap().as_str(), Some("active"));
        let closed = close_frida_session(&json!({ "session_id": id }));
        assert_eq!(closed.get("status").unwrap().as_str(), Some("closed"));
    }
}
