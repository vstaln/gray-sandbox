//! gray-sandbox — run bash commands under bubblewrap.
//!
//! Port of the policy core of pi's `sandbox/` extension (MIT). The original
//! rebuilt the bash tool around @anthropic-ai/sandbox-runtime; a sidecar
//! can't replace tools, so `tool/before` on `bash` answers
//! `{decision:"modify"}` wrapping the command:
//!
//!   bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
//!         [--ro-bind <p> <p>]… [--bind <p> <p>]… \
//!         --bind <cwd> <cwd> --chdir <cwd> [--unshare-net] \
//!         -- bash -lc '<quoted command>'
//!
//! Everything is read-only except the session cwd (and configured extras);
//! `--unshare-net` is applied unless config `network` is true.
//!
//! Config: ~/.gray/sandbox/config.json —
//!   {"enabled": true, "network": false, "extra_ro": [], "extra_rw": []}
//! `/sandbox on|off|net on|net off|ro <path>|rw <path>|status`.
//!
//! Rules: never sandbox a command already invoking bwrap/sudo; never
//! sandbox when `bwrap` isn't on PATH (host/say once per session instead,
//! capability host.say); fail OPEN on any internal error — a broken
//! sandbox must not brick bash.

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

use serde_json::{Value, json};

fn manifest() -> Value {
    json!({
        "name": "sandbox",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "2.0",
        "tools": [],
        "commands": ["/sandbox"],
        "hooks": ["tool/before"],
        "capabilities": ["host.say"],
    })
}

// ── config ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct Config {
    enabled: bool,
    network: bool,
    extra_ro: Vec<String>,
    extra_rw: Vec<String>,
}

fn state_dir() -> PathBuf {
    std::env::var_os("GRAY_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".gray")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sandbox")
}

fn config_file() -> PathBuf {
    state_dir().join("config.json")
}

/// Defaults when the file is absent or unreadable: sandbox on, no network.
fn load_config() -> Config {
    let Ok(s) = std::fs::read_to_string(config_file()) else {
        return Config { enabled: true, ..Default::default() };
    };
    let v: Value = serde_json::from_str(&s).unwrap_or(Value::Null);
    let list = |key: &str| {
        v.get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    };
    Config {
        enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        network: v.get("network").and_then(Value::as_bool).unwrap_or(false),
        extra_ro: list("extra_ro"),
        extra_rw: list("extra_rw"),
    }
}

fn save_config(cfg: &Config) -> std::io::Result<()> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        config_file(),
        serde_json::to_string_pretty(&json!({
            "enabled": cfg.enabled,
            "network": cfg.network,
            "extra_ro": cfg.extra_ro,
            "extra_rw": cfg.extra_rw,
        }))? + "\n",
    )
}

// ── host/say (once per session) ─────────────────────────────────────────

/// Sidecar→host requests queued for the main loop to write to stdout.
static OUTBOX: LazyLock<Mutex<Vec<Value>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static WARNED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

fn say_once(session: &str, text: &str) {
    let mut warned = WARNED.lock().expect("warned");
    if !warned.insert(session.to_string()) {
        return;
    }
    let id = format!("say{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    OUTBOX
        .lock()
        .expect("outbox")
        .push(json!({"id": id, "method": "host/say", "params": {"text": text}}));
}

// ── wrapping ────────────────────────────────────────────────────────────

fn have_bwrap() -> bool {
    std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p).any(|d| {
                let f = d.join("bwrap");
                f.is_file()
                    && std::os::unix::fs::PermissionsExt::mode(
                        &f.metadata().map(|m| m.permissions()).unwrap_or_else(|_| {
                            std::fs::Permissions::from(std::os::unix::fs::PermissionsExt::from_mode(0))
                        }),
                    ) & 0o111
                        != 0
            })
        })
        .unwrap_or(false)
}

/// Any whitespace token invoking bwrap/sudo (basename, so /usr/bin/sudo
/// counts too) — sandboxing those must never happen.
fn invokes_forbidden(command: &str) -> bool {
    command
        .split(|c: char| c.is_whitespace() || matches!(c, '|' | ';' | '&'))
        .filter_map(|t| t.rsplit('/').next())
        .any(|t| matches!(t, "bwrap" | "sudo"))
}

/// Shell single-quote: abc'def -> 'abc'\''def'
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn expand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest).to_string_lossy().into_owned();
    }
    p.to_string()
}

/// Build the wrapped command, or None to leave it alone.
fn wrap(command: &str, cwd: &str, cfg: &Config) -> Option<String> {
    if cwd.is_empty() || !Path::new(cwd).is_dir() || invokes_forbidden(command) {
        return None;
    }
    let mut out = String::from("bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp");
    for (flag, paths) in [("--ro-bind", &cfg.extra_ro), ("--bind", &cfg.extra_rw)] {
        for p in paths {
            let p = expand_home(p);
            if Path::new(&p).exists() {
                out.push_str(&format!(" {flag} {0} {0}", shq(&p)));
            }
        }
    }
    out.push_str(&format!(" --bind {0} {0} --chdir {0}", shq(cwd)));
    if !cfg.network {
        out.push_str(" --unshare-net");
    }
    out.push_str(&format!(" -- bash -lc {}", shq(command)));
    Some(out)
}

// ── wire ────────────────────────────────────────────────────────────────

fn tool_before(params: &Value) -> Value {
    let cfg = load_config();
    if !cfg.enabled || params.get("name").and_then(Value::as_str) != Some("bash") {
        return json!({"decision": "allow"});
    }
    if !have_bwrap() {
        let sid = params
            .get("session")
            .and_then(|s| s.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        say_once(sid, "bwrap not installed, sandbox off");
        return json!({"decision": "allow"});
    }
    let command = params
        .get("args")
        .and_then(|a| a.get("command"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let cwd = params
        .get("session")
        .and_then(|s| s.get("cwd"))
        .and_then(Value::as_str)
        .unwrap_or("");
    match wrap(command, cwd, &cfg) {
        Some(new) => json!({
            "decision": "modify",
            "args": { "command": new }
        }),
        None => json!({"decision": "allow"}),
    }
}

/// `/sandbox …` — `argv` excludes the command name.
fn run_command(argv: &[&str]) -> String {
    let mut cfg = load_config();
    let save = |cfg: &Config, msg: String| match save_config(cfg) {
        Ok(()) => msg,
        Err(e) => format!("couldn't write {}: {e}", config_file().display()),
    };
    match argv {
        ["on"] => {
            cfg.enabled = true;
            save(&cfg, "sandbox on".into())
        }
        ["off"] => {
            cfg.enabled = false;
            save(&cfg, "sandbox off".into())
        }
        ["net", "on"] => {
            cfg.network = true;
            save(&cfg, "sandbox network on (no --unshare-net)".into())
        }
        ["net", "off"] => {
            cfg.network = false;
            save(&cfg, "sandbox network off (--unshare-net)".into())
        }
        ["ro", path] => {
            cfg.extra_ro.push(path.to_string());
            save(&cfg, format!("read-only bind added: {path}"))
        }
        ["rw", path] => {
            cfg.extra_rw.push(path.to_string());
            save(&cfg, format!("writable bind added: {path}"))
        }
        _ => format!(
            "gray-sandbox {} — {} | network {} | bwrap {} | ro [{}] rw [{}]\n\
             /sandbox on|off · net on|off · ro <path> · rw <path> · status",
            env!("CARGO_PKG_VERSION"),
            if cfg.enabled { "ON" } else { "OFF" },
            if cfg.network { "allowed" } else { "unshared" },
            if have_bwrap() { "present" } else { "MISSING" },
            cfg.extra_ro.join(", "),
            cfg.extra_rw.join(", "),
        ),
    }
}

/// One request → `Some(reply)`, or `None` for notifications and for the
/// host's responses to our own host/* requests. The bool asks the loop to
/// exit after writing the reply.
fn handle(req: &Value) -> (Option<Value>, bool) {
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return (None, false); // response to a sidecar→host request
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let Some(id) = req.get("id").cloned() else {
        return (None, method == "plugin/shutdown");
    };
    let result = match method {
        "plugin/manifest" => manifest(),
        "tool/before" => tool_before(&params),
        "command/run" => {
            let argv: Vec<&str> = params
                .get("argv")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            json!({ "text": run_command(&argv) })
        }
        "plugin/shutdown" => return (Some(json!({ "id": id, "result": {} })), true),
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            return (Some(json!({ "id": id, "error": error })), false);
        }
    };
    (Some(json!({ "id": id, "result": result })), false)
}

fn main() -> std::io::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        println!("{}", manifest());
        return Ok(());
    }
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
        let (reply, exit) = handle(&req);
        for msg in OUTBOX.lock().expect("outbox").drain(..) {
            writeln!(stdout, "{msg}")?;
        }
        if let Some(reply) = reply {
            writeln!(stdout, "{reply}")?;
        }
        stdout.flush()?;
        if exit {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(method: &str, params: Value) -> Value {
        handle(&json!({ "id": 1, "method": method, "params": params }))
            .0
            .unwrap()
    }

    fn cfg(enabled: bool, network: bool) -> Config {
        Config { enabled, network, extra_ro: vec![], extra_rw: vec![] }
    }

    #[test]
    fn manifest_shape() {
        let m = manifest();
        assert_eq!(m["name"], "sandbox");
        assert_eq!(m["hooks"], json!(["tool/before"]));
        assert_eq!(m["commands"], json!(["/sandbox"]));
        assert_eq!(m["capabilities"], json!(["host.say"]));
    }

    #[test]
    fn wrap_builds_bwrap_command() {
        let dir = std::env::temp_dir().join(format!("gray-sbx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cwd = dir.to_str().unwrap();
        let w = wrap("ls -la", cwd, &cfg(true, false)).unwrap();
        assert!(w.starts_with("bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp"));
        assert!(w.contains(&format!("--bind {0} {0} --chdir {0}", shq(cwd))));
        assert!(w.contains("--unshare-net"));
        assert!(w.ends_with("-- bash -lc 'ls -la'"));
    }

    #[test]
    fn network_true_drops_unshare() {
        let w = wrap("ls", "/tmp", &cfg(true, true)).unwrap();
        assert!(!w.contains("--unshare-net"));
    }

    #[test]
    fn extras_bind_when_they_exist() {
        let mut c = cfg(true, false);
        c.extra_ro = vec!["/etc".into(), "/nonexistent-xyz".into()];
        c.extra_rw = vec!["/tmp".into()];
        let w = wrap("ls", "/tmp", &c).unwrap();
        assert!(w.contains("--ro-bind '/etc' '/etc'"));
        assert!(w.contains("--bind '/tmp' '/tmp'"));
        assert!(!w.contains("nonexistent-xyz"));
    }

    #[test]
    fn quoting_is_shell_safe() {
        let w = wrap("echo 'hi there'", "/tmp", &cfg(true, false)).unwrap();
        assert!(w.ends_with(r#"-- bash -lc 'echo '\''hi there'\'''"#));
    }

    #[test]
    fn bwrap_and_sudo_never_wrapped() {
        for cmd in ["sudo apt update", "bwrap -- ls", "x | sudo tee f", "/usr/bin/sudo ls"] {
            assert!(wrap(cmd, "/tmp", &cfg(true, false)).is_none(), "for {cmd}");
        }
        assert!(wrap("sudoers", "/tmp", &cfg(true, false)).is_some());
    }

    #[test]
    fn missing_cwd_allows() {
        assert!(wrap("ls", "", &cfg(true, false)).is_none());
        assert!(wrap("ls", "/nonexistent-dir-xyz", &cfg(true, false)).is_none());
    }

    #[test]
    fn non_bash_allows() {
        let r = call("tool/before", json!({"name": "read", "args": {}, "session": {}}));
        assert_eq!(r["result"]["decision"], "allow");
    }

    #[test]
    fn responses_to_host_requests_are_ignored() {
        let (reply, exit) = handle(&json!({"id": "say1", "result": {}}));
        assert!(reply.is_none() && !exit);
        let (reply, exit) = handle(&json!({"id": "say2", "error": {"code": -1, "message": "denied"}}));
        assert!(reply.is_none() && !exit);
    }

    #[test]
    fn say_once_fires_once_per_session() {
        say_once("sess-x", "hello");
        say_once("sess-x", "hello again");
        say_once("sess-y", "hi y");
        let n = OUTBOX.lock().unwrap().len();
        assert_eq!(n, 2, "one say per session, got {n}");
    }

    #[test]
    fn shutdown_replies_then_exits() {
        let (reply, exit) = handle(&json!({ "id": 2, "method": "plugin/shutdown" }));
        assert!(reply.is_some() && exit);
    }
}
