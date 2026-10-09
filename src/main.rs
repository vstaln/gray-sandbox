//! gray-sandbox — run bash commands under bubblewrap.
//!
//! Modeled on Anthropic's `sandbox-runtime` (MIT): read-only root, the
//! session cwd plus toolchain caches writable, sensitive paths shadowed,
//! and a network mode of `on` | `off` | `allowlist` where `allowlist`
//! runs a filtering CONNECT proxy (srt uses the same mechanism; their
//! bridge is socat, so this one is too).
//!
//! A sidecar cannot replace the built-in bash tool, so `tool/before` on
//! `bash` answers `{decision:"modify"}` and wraps the command:
//!
//!   bwrap --die-with-parent --ro-bind / / --dev /dev --proc /proc \
//!         --tmpfs /tmp [--ro-bind p p]… [--bind p p]… --bind cwd cwd \
//!         [--tmpfs <denied-dir> | --ro-bind /dev/null <denied-file>]… \
//!         --chdir cwd [--unshare-net] --setenv GRAY_SANDBOX nested \
//!         -- bash -lc '<quoted command>'
//!
//! Network `allowlist` mode adds `--unshare-net` plus a socat bridge the
//! child sees as `http_proxy=http://127.0.0.1:18080` → unix socket → the
//! sidecar's own CONNECT proxy, which checks `allowed_domains`/
//! `denied_domains` per request (exact or `*.suffix`, both spellings
//! `allowedDomains`/`allowed_domains` accepted). Requires `socat` inside
//! the sandbox; when missing the mode fails CLOSED (no network) and the
//! user is told once via host/say.
//!
//! Processes spawned inside a sandboxed command (e.g. `gray -p` workers,
//! subagent runs) inherit `GRAY_SANDBOX=nested` and skip wrapping — they
//! are already confined by the outer bwrap, so nesting gains nothing.
//! `GRAY_SANDBOX=off` is the manual escape hatch.
//!
//! Config: ~/.gray/sandbox/config.json — flat or nested keys both read:
//!   {"enabled": true, "network": "on"|"off"|"allowlist"|true|false
//!     | {"allowedDomains": [...], "deniedDomains": [...]},
//!    "filesystem": {"denyRead": [...], "allowWrite": [...], "denyWrite": [...]},
//!    "extra_ro": [], "extra_rw": [], "passthrough": []}
//! `/sandbox on|off · net on|off|allowlist · allow|deny <domain> ·
//!          ro|rw <path> · deny-read <path> · deny-write <glob> · status`.
//!
//! Rules: never sandbox a passthrough command (bwrap/sudo/container
//! runtimes); never sandbox without `bwrap` on PATH (host/say once,
//! capability host.say); fail OPEN on internal errors — a broken sandbox
//! must not brick bash — EXCEPT allowlist-without-socat, which fails
//! closed because silently opening the network is worse.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, Once};
use std::time::Duration;

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NetMode {
    On,
    Off,
    Allowlist,
}

struct Config {
    enabled: bool,
    net_mode: NetMode,
    allowed_domains: Vec<String>,
    denied_domains: Vec<String>,
    deny_read: Vec<String>,
    deny_write: Vec<String>,
    extra_ro: Vec<String>,
    extra_rw: Vec<String>,
    passthrough: Vec<String>,
}

/// Upstream (sandbox-runtime) default allowlist: package registries +
/// GitHub. Extend via `/sandbox allow <domain>` or config.
const DEFAULT_ALLOWED: &[&str] = &[
    "npmjs.org", "*.npmjs.org", "registry.npmjs.org", "registry.yarnpkg.com",
    "pypi.org", "*.pypi.org", "github.com", "*.github.com", "api.github.com",
    "raw.githubusercontent.com",
];

/// Credential paths shadowed by default. Deviation from upstream: `~/.ssh`
/// is NOT denied — git-over-ssh is a supported workflow; add it with
/// `/sandbox deny-read ~/.ssh` if unwanted.
const DEFAULT_DENY_READ: &[&str] = &["~/.aws", "~/.gnupg", "~/.netrc", "~/.docker"];

/// Basename globs denied WRITE (matched against existing cwd entries at
/// wrap time — files created inside a writable dir later are not covered).
const DEFAULT_DENY_WRITE: &[&str] = &[".env", ".env.*", "*.pem", "*.key"];

/// Commands never sandboxed (namespace/container tools would escape or
/// break anyway).
const DEFAULT_PASSTHROUGH: &[&str] =
    &["bwrap", "sudo", "doas", "socat", "docker", "podman", "nerdctl", "buildah", "systemd-run"];

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

fn list_key(v: &Value, keys: &[&str]) -> Vec<String> {
    for k in keys {
        if let Some(a) = v.get(*k).and_then(Value::as_array) {
            return a.iter().filter_map(Value::as_str).map(str::to_string).collect();
        }
    }
    Vec::new()
}

/// Parse `network` in every accepted spelling: bool (legacy), mode
/// string, or the upstream `{allowedDomains, deniedDomains}` object
/// (object ⇒ allowlist).
fn parse_network(v: Option<&Value>) -> (NetMode, Vec<String>, Vec<String>) {
    match v {
        Some(Value::Bool(true)) | None => (NetMode::On, vec![], vec![]),
        Some(Value::Bool(false)) => (NetMode::Off, vec![], vec![]),
        Some(Value::String(s)) => (
            match s.as_str() {
                "off" => NetMode::Off,
                "allowlist" | "allow-list" | "filtered" => NetMode::Allowlist,
                _ => NetMode::On,
            },
            vec![],
            vec![],
        ),
        Some(Value::Object(_)) => (
            NetMode::Allowlist,
            list_key(v.unwrap(), &["allowed_domains", "allowedDomains", "allowed"]),
            list_key(v.unwrap(), &["denied_domains", "deniedDomains", "denied"]),
        ),
        _ => (NetMode::On, vec![], vec![]),
    }
}

/// Defaults when the file is absent or unreadable: on, network on,
/// upstream deny/allow defaults.
fn load_config() -> Config {
    let defaults = |net_mode: NetMode| Config {
        enabled: true,
        net_mode,
        allowed_domains: DEFAULT_ALLOWED.iter().map(|s| s.to_string()).collect(),
        denied_domains: vec![],
        deny_read: DEFAULT_DENY_READ.iter().map(|s| s.to_string()).collect(),
        deny_write: DEFAULT_DENY_WRITE.iter().map(|s| s.to_string()).collect(),
        extra_ro: vec![],
        extra_rw: vec![],
        passthrough: DEFAULT_PASSTHROUGH.iter().map(|s| s.to_string()).collect(),
    };
    let Ok(s) = std::fs::read_to_string(config_file()) else {
        return defaults(NetMode::On);
    };
    let v: Value = serde_json::from_str(&s).unwrap_or(Value::Null);
    let fs = v.get("filesystem").cloned().unwrap_or(json!({}));
    let (net_mode, allowed, denied) = parse_network(v.get("network"));
    let mut allowed_domains = if allowed.is_empty() && net_mode != NetMode::Allowlist {
        vec![]
    } else {
        allowed
    };
    let denied_domains = denied;
    // domain lists also accepted at top level (flat style)
    if allowed_domains.is_empty() {
        allowed_domains = list_key(&v, &["allowed_domains", "allowedDomains"]);
    }
    let denied_domains = if denied_domains.is_empty() {
        list_key(&v, &["denied_domains", "deniedDomains"])
    } else {
        denied_domains
    };
    if matches!(v.get("network"), Some(Value::Object(_))) && net_mode == NetMode::Allowlist
        && allowed_domains.is_empty()
    {
        allowed_domains = DEFAULT_ALLOWED.iter().map(|s| s.to_string()).collect();
    }
    let mut cfg = defaults(net_mode);
    cfg.enabled = v.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    cfg.allowed_domains = allowed_domains;
    cfg.denied_domains = denied_domains;
    let deny_read = list_key(&fs, &["deny_read", "denyRead"]);
    if !deny_read.is_empty() {
        cfg.deny_read = deny_read;
    }
    let deny_write = list_key(&fs, &["deny_write", "denyWrite"]);
    if !deny_write.is_empty() {
        cfg.deny_write = deny_write;
    }
    // allowWrite adds to the writable set alongside extra_rw.
    cfg.extra_rw = list_key(&fs, &["allow_write", "allowWrite"]);
    cfg.extra_rw.extend(list_key(&v, &["extra_rw", "extraRw"]));
    cfg.extra_ro = list_key(&v, &["extra_ro", "extraRo"]);
    let passthrough = list_key(&v, &["passthrough", "excludedCommands"]);
    if !passthrough.is_empty() {
        cfg.passthrough = passthrough;
    }
    cfg
}

fn save_config(cfg: &Config) -> std::io::Result<()> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir)?;
    let net = match cfg.net_mode {
        NetMode::Allowlist => json!({
            "mode": "allowlist",
            "allowed_domains": cfg.allowed_domains,
            "denied_domains": cfg.denied_domains,
        }),
        NetMode::On => json!("on"),
        NetMode::Off => json!("off"),
    };
    std::fs::write(
        config_file(),
        serde_json::to_string_pretty(&json!({
            "enabled": cfg.enabled,
            "network": net,
            "filesystem": {"deny_read": cfg.deny_read, "deny_write": cfg.deny_write},
            "extra_ro": cfg.extra_ro,
            "extra_rw": cfg.extra_rw,
            "passthrough": cfg.passthrough,
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
    if !warned.insert(format!("{session}:{text}")) {
        return;
    }
    let id = format!("say{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    OUTBOX
        .lock()
        .expect("outbox")
        .push(json!({"id": id, "method": "host/say", "params": {"text": text}}));
}

// ── domain matching ─────────────────────────────────────────────────────

/// `*.github.com` matches `api.github.com` AND bare `github.com`;
/// a plain pattern matches exactly. Port is stripped before matching.
fn domain_matches(pattern: &str, host: &str) -> bool {
    let host = host.split(':').next().unwrap_or(host).to_lowercase();
    let pat = pattern.to_lowercase();
    if let Some(suffix) = pat.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pat
    }
}

fn domain_allowed(host: &str, cfg: &Config) -> bool {
    if cfg.denied_domains.iter().any(|p| domain_matches(p, host)) {
        return false;
    }
    cfg.allowed_domains.iter().any(|p| domain_matches(p, host))
}

// ── filtering CONNECT proxy (network `allowlist` mode) ──────────────────

const PROXY_PORT: u16 = 18080;
static PROXY_STARTED: Once = Once::new();

fn proxy_sock() -> PathBuf {
    state_dir().join("run").join("proxy.sock")
}

/// Lazily bind the unix-socket CONNECT proxy once per sidecar lifetime.
/// Domain lists are read from config per request, so `/sandbox allow …`
/// takes effect immediately.
fn ensure_proxy() {
    PROXY_STARTED.call_once(|| {
        let dir = proxy_sock().parent().unwrap().to_path_buf();
        let _ = std::fs::create_dir_all(&dir);
        let sock = proxy_sock();
        let _ = std::fs::remove_file(&sock);
        let Ok(listener) = UnixListener::bind(&sock) else {
            eprintln!("gray-sandbox: cannot bind {}", sock.display());
            return;
        };
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                std::thread::spawn(move || handle_conn(conn));
            }
        });
    });
}

/// One proxied connection: read the request head, CONNECT-filter, tunnel.
fn handle_conn(stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut head = String::new();
    let mut byte = [0u8; 1];
    // request head ends at \r\n\r\n; cap the scan at 8KiB
    while !head.ends_with("\r\n\r\n") && head.len() < 8192 {
        match reader.read(&mut byte) {
            Ok(1) => head.push(byte[0] as char),
            _ => break,
        }
    }
    let line = head.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !method.eq_ignore_ascii_case("connect") {
        let _ = (&mut reader.get_ref()).write_all(
            b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n",
        );
        return;
    }
    let host = target.split(':').next().unwrap_or("").to_string();
    let port: u16 = target
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);
    let cfg = load_config();
    if !domain_allowed(&host, &cfg) {
        let _ = (&mut reader.get_ref()).write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
        );
        return;
    }
    let addr = format!("{host}:{port}");
    let Ok(upstream) = TcpStream::connect_timeout(
        &match addr.parse() {
            Ok(a) => a,
            Err(_) => {
                // hostname — resolve through the system resolver
                match std::net::ToSocketAddrs::to_socket_addrs(&addr.as_str()) {
                    Ok(mut it) => match it.next() {
                        Some(a) => a,
                        None => return,
                    },
                    Err(_) => return,
                }
            }
        },
        Duration::from_secs(10),
    ) else {
        let _ = (&mut reader.get_ref())
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        return;
    };
    if (&mut reader.get_ref())
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    // Duplex pump: client→upstream on a thread, upstream→client here.
    let mut client = reader.into_inner();
    let _ = client.set_read_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let Ok(mut up2) = upstream.try_clone() else { return };
    let mut client2 = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client2, &mut up2);
        let _ = up2.shutdown(Shutdown::Both);
    });
    let mut up_read = upstream;
    let _ = std::io::copy(&mut up_read, &mut client);
    let _ = client.shutdown(Shutdown::Both);
    let _ = t.join();
}

// ── wrapping ────────────────────────────────────────────────────────────

fn have_tool(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p).any(|d| {
                let f = d.join(name);
                f.is_file()
                    && std::os::unix::fs::PermissionsExt::mode(
                        &f.metadata()
                            .map(|m| m.permissions())
                            .unwrap_or_else(|_| {
                                std::fs::Permissions::from(
                                    std::os::unix::fs::PermissionsExt::from_mode(0),
                                )
                            }),
                    ) & 0o111
                        != 0
            })
        })
        .unwrap_or(false)
}

/// Any whitespace/pipe token invoking a passthrough command (basename, so
/// /usr/bin/sudo counts too) — sandboxing those must never happen.
fn invokes_passthrough(command: &str, list: &[String]) -> bool {
    command
        .split(|c: char| c.is_whitespace() || matches!(c, '|' | ';' | '&'))
        .filter_map(|t| t.rsplit('/').next())
        .any(|t| list.iter().any(|p| p == t))
}

/// Shell single-quote: abc'def -> 'abc'\''def'
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Home dirs dev tooling must write (build caches, installs, gray's own
/// state). Always bound read-write when they exist — user `extra_rw` /
/// `filesystem.allowWrite` adds more. Everything else under $HOME stays
/// read-only.
fn default_rw() -> Vec<String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    [
        ".cache", ".cargo", ".rustup", ".npm", ".bun", ".deno", ".local",
        ".gray", ".config/pip", "go", ".m2", ".gradle", ".venv", ".poetry",
        ".cache/go-build", ".gitconfig",
    ]
    .iter()
    .map(|r| home.join(r).to_string_lossy().into_owned())
    .filter(|p| Path::new(p).exists())
    .collect()
}

fn expand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest).to_string_lossy().into_owned();
    }
    p.to_string()
}

/// Basename glob for `denyWrite` patterns: `*`/`?` only.
fn glob_match(pat: &str, name: &str) -> bool {
    fn inner(p: &[u8], n: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (Some(b'*'), _) => {
                inner(&p[1..], n) || (!n.is_empty() && inner(p, &n[1..]))
            }
            (Some(b'?'), Some(_)) => inner(&p[1..], &n[1..]),
            (Some(a), Some(b)) => a == b && inner(&p[1..], &n[1..]),
            (None, None) => true,
            _ => false,
        }
    }
    inner(pat.as_bytes(), name.as_bytes())
}

/// Paths (already expanded) matched by `deny_write` globs in `cwd`.
/// Top-level entries only — the mount table can only shadow what exists
/// at wrap time.
fn deny_write_paths(cwd: &str, globs: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(cwd) else { return out };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if globs.iter().any(|g| glob_match(g, &name)) {
            out.push(e.path());
        }
    }
    out
}

/// Build the wrapped command, or None to leave it alone.
fn wrap(command: &str, cwd: &str, cfg: &Config, session: &str) -> Option<String> {
    // Inherited by every child of a sandboxed command — inner grays,
    // spawned workers, subagents: all already confined. `off`/`0` are the
    // manual escape hatch (and `nested` the automatic one).
    if matches!(
        std::env::var("GRAY_SANDBOX").as_deref(),
        Ok("off") | Ok("0") | Ok("nested")
    ) || cwd.is_empty()
        || !Path::new(cwd).is_dir()
        || invokes_passthrough(command, &cfg.passthrough)
    {
        return None;
    }
    let mut out = String::from(
        "bwrap --die-with-parent --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp",
    );
    let mut rw = default_rw();
    rw.extend(cfg.extra_rw.iter().cloned());
    for (flag, paths) in [("--ro-bind", &cfg.extra_ro), ("--bind", &rw)] {
        for p in paths {
            let p = expand_home(p);
            if Path::new(&p).exists() {
                out.push_str(&format!(" {flag} {0} {0}", shq(&p)));
            }
        }
    }
    out.push_str(&format!(" --bind {0} {0}", shq(cwd)));
    // Deny binds come last so they shadow writable parents.
    let mut denied: Vec<String> = cfg.deny_read.iter().map(|p| expand_home(p)).collect();
    denied.extend(
        deny_write_paths(cwd, &cfg.deny_write)
            .iter()
            .map(|p| p.to_string_lossy().into_owned()),
    );
    for p in denied {
        if !Path::new(&p).exists() {
            continue;
        }
        if Path::new(&p).is_dir() {
            out.push_str(&format!(" --tmpfs {0}", shq(&p)));
        } else {
            out.push_str(&format!(" --ro-bind /dev/null {0}", shq(&p)));
        }
    }
    out.push_str(&format!(" --chdir {0}", shq(cwd)));

    let tail = match cfg.net_mode {
        NetMode::On => format!(" -- bash -lc {}", shq(command)),
        NetMode::Off => format!(" --unshare-net -- bash -lc {}", shq(command)),
        NetMode::Allowlist => {
            if !have_tool("socat") {
                say_once(
                    session,
                    "sandbox net allowlist needs socat in the sandbox — failing closed (no network)",
                );
                format!(" --unshare-net -- bash -lc {}", shq(command))
            } else {
                ensure_proxy();
                let sock = proxy_sock().to_string_lossy().into_owned();
                format!(
                    " --unshare-net \
                     --setenv http_proxy http://127.0.0.1:{port} \
                     --setenv https_proxy http://127.0.0.1:{port} \
                     --setenv all_proxy http://127.0.0.1:{port} \
                     --setenv no_proxy 127.0.0.1,localhost \
                     -- bash -c {} ",
                    shq(&format!(
                        "socat TCP-LISTEN:{},fork,bind=127.0.0.1,reuseaddr \
                         UNIX-CONNECT:{} </dev/null >/dev/null 2>&1 & exec bash -lc {}",
                        PROXY_PORT, sock, shq(command)
                    )),
                    port = PROXY_PORT,
                )
            }
        }
    };
    out.push_str(&format!(" --setenv GRAY_SANDBOX nested{tail}"));
    Some(out)
}

// ── wire ────────────────────────────────────────────────────────────────

fn tool_before(params: &Value) -> Value {
    let cfg = load_config();
    if !cfg.enabled || params.get("name").and_then(Value::as_str) != Some("bash") {
        return json!({"decision": "allow"});
    }
    let sid = params
        .get("session")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !have_tool("bwrap") {
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
    match wrap(command, cwd, &cfg, sid) {
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
            cfg.net_mode = NetMode::On;
            save(&cfg, "sandbox network on".into())
        }
        ["net", "off"] => {
            cfg.net_mode = NetMode::Off;
            save(&cfg, "sandbox network off (--unshare-net)".into())
        }
        ["net", "allowlist"] | ["net", "allow"] | ["net", "filtered"] => {
            cfg.net_mode = NetMode::Allowlist;
            save(&cfg, "sandbox network allowlist (CONNECT proxy + socat bridge)".into())
        }
        ["allow", d] | ["net", "allow", d] => {
            cfg.allowed_domains.push(d.to_string());
            if cfg.net_mode == NetMode::On {
                cfg.net_mode = NetMode::Allowlist;
            }
            save(&cfg, format!("allowlisted {d} (net mode: allowlist)"))
        }
        ["deny", d] | ["net", "deny", d] => {
            cfg.denied_domains.push(d.to_string());
            save(&cfg, format!("denylisted {d}"))
        }
        ["ro", path] => {
            cfg.extra_ro.push(path.to_string());
            save(&cfg, format!("read-only bind added: {path}"))
        }
        ["rw", path] => {
            cfg.extra_rw.push(path.to_string());
            save(&cfg, format!("writable bind added: {path}"))
        }
        ["deny-read", path] => {
            cfg.deny_read.push(path.to_string());
            save(&cfg, format!("deny-read added: {path}"))
        }
        ["deny-write", glob] => {
            cfg.deny_write.push(glob.to_string());
            save(&cfg, format!("deny-write glob added: {glob}"))
        }
        _ => format!(
            "gray-sandbox {} — {} | net {} | bwrap {} | socat {}\n\
             domains: allow [{}] deny [{}]\n\
             deny-read [{}] deny-write [{}]\n\
             ro [{}] rw [{}]\n\
             /sandbox on|off · net on|off|allowlist · allow|deny <domain>\n\
             ro|rw <path> · deny-read <path> · deny-write <glob> · status",
            env!("CARGO_PKG_VERSION"),
            if cfg.enabled { "ON" } else { "OFF" },
            match cfg.net_mode {
                NetMode::On => "on",
                NetMode::Off => "off",
                NetMode::Allowlist => "allowlist",
            },
            if have_tool("bwrap") { "present" } else { "MISSING" },
            if have_tool("socat") { "present" } else { "missing" },
            cfg.allowed_domains.join(", "),
            cfg.denied_domains.join(", "),
            cfg.deny_read.join(", "),
            cfg.deny_write.join(", "),
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

    /// Serializes tests that mutate GRAY_HOME / GRAY_SANDBOX.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn call(method: &str, params: Value) -> Value {
        handle(&json!({ "id": 1, "method": method, "params": params }))
            .0
            .unwrap()
    }

    fn cfg(net_mode: NetMode) -> Config {
        Config {
            enabled: true,
            net_mode,
            allowed_domains: vec!["github.com".into(), "*.npmjs.org".into()],
            denied_domains: vec![],
            deny_read: vec![],
            deny_write: vec![],
            extra_ro: vec![],
            extra_rw: vec![],
            passthrough: DEFAULT_PASSTHROUGH.iter().map(|s| s.to_string()).collect(),
        }
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
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("GRAY_SANDBOX") };
        let dir = std::env::temp_dir().join(format!("gray-sbx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cwd = dir.to_str().unwrap();
        let w = wrap("ls -la", cwd, &cfg(NetMode::Off), "t").unwrap();
        assert!(w.starts_with(
            "bwrap --die-with-parent --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp"
        ));
        assert!(w.contains(&format!("--bind {0} {0}", shq(cwd))));
        assert!(w.contains(&format!("--chdir {0}", shq(cwd))));
        assert!(w.contains("--unshare-net"));
        assert!(w.ends_with(&format!("-- bash -lc {}", shq("ls -la"))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn network_on_drops_unshare() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("GRAY_SANDBOX") };
        let dir = std::env::temp_dir().join(format!("gray-sbx-n-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let w = wrap("ls", dir.to_str().unwrap(), &cfg(NetMode::On), "t").unwrap();
        assert!(!w.contains("--unshare-net"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_guard_skips_wrap() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gray-sbx-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("GRAY_SANDBOX", "nested") };
        assert!(wrap("ls", dir.to_str().unwrap(), &cfg(NetMode::On), "t").is_none());
        unsafe { std::env::set_var("GRAY_SANDBOX", "off") };
        assert!(wrap("ls", dir.to_str().unwrap(), &cfg(NetMode::On), "t").is_none());
        unsafe { std::env::remove_var("GRAY_SANDBOX") };
        assert!(wrap("ls", dir.to_str().unwrap(), &cfg(NetMode::On), "t").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn passthrough_never_sandboxed() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("GRAY_SANDBOX") };
        let dir = std::env::temp_dir().join(format!("gray-sbx-pt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = cfg(NetMode::On);
        assert!(wrap("sudo ls", dir.to_str().unwrap(), &c, "t").is_none());
        assert!(wrap("ls | docker", dir.to_str().unwrap(), &c, "t").is_none());
        assert!(wrap("ls -la", dir.to_str().unwrap(), &c, "t").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_wrap_bridges_socat() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("GRAY_SANDBOX") };
        let dir = std::env::temp_dir().join(format!("gray-sbx-al-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let w = wrap("npm i", dir.to_str().unwrap(), &cfg(NetMode::Allowlist), "t").unwrap();
        assert!(w.contains("--unshare-net"));
        if have_tool("socat") {
            assert!(w.contains("http://127.0.0.1:18080"));
            assert!(w.contains("socat TCP-LISTEN:18080"));
            assert!(w.contains("UNIX-CONNECT:"));
        } else {
            // no socat → fails closed: still unshared, no proxy env
            assert!(!w.contains("http_proxy"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deny_binds_shadow_files_and_dirs() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("GRAY_SANDBOX") };
        let dir = std::env::temp_dir().join(format!("gray-sbx-d-{}", std::process::id()));
        let cwd = dir.to_str().unwrap().to_string();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("prod.env"), "x").unwrap();
        std::fs::write(dir.join("keep.txt"), "x").unwrap();
        let mut c = cfg(NetMode::On);
        c.deny_write = vec!["*.env".into()];
        let w = wrap("ls", &cwd, &c, "t").unwrap();
        assert!(w.contains(&format!("--ro-bind /dev/null {}", shq(&dir.join("prod.env").to_string_lossy()))));
        assert!(!w.contains("keep.txt"));
        // deny binds come after the writable cwd bind
        assert!(w.find("--bind").unwrap() < w.find("prod.env").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn domain_matching() {
        assert!(domain_matches("github.com", "github.com"));
        assert!(!domain_matches("github.com", "api.github.com"));
        assert!(domain_matches("*.github.com", "api.github.com"));
        assert!(domain_matches("*.github.com", "github.com"));
        assert!(domain_matches("*.npmjs.org", "registry.npmjs.org:443"));
        assert!(!domain_matches("*.npmjs.org", "evil.npmjs.org.evil.com"));
    }

    #[test]
    fn parse_network_shapes() {
        assert!(matches!(parse_network(Some(&json!(false))).0, NetMode::Off));
        assert!(matches!(parse_network(Some(&json!(true))).0, NetMode::On));
        assert!(matches!(parse_network(Some(&json!("allowlist"))).0, NetMode::Allowlist));
        let (m, a, _d) = parse_network(Some(&json!({
            "allowedDomains": ["github.com"], "deniedDomains": ["x.evil"]
        })));
        assert!(matches!(m, NetMode::Allowlist));
        assert_eq!(a, vec!["github.com"]);
    }

    #[test]
    fn absent_config_defaults_on_with_network() {
        let dir = std::env::temp_dir().join(format!("gray-sbx-noconf-{}", std::process::id()));
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("GRAY_HOME", &dir) };
        let c = load_config();
        unsafe { std::env::remove_var("GRAY_HOME") };
        assert!(c.enabled);
        assert!(matches!(c.net_mode, NetMode::On));
        assert!(!c.deny_read.is_empty());
    }

    #[test]
    fn default_rw_covers_toolchains() {
        for p in default_rw() {
            let home = std::env::var_os("HOME").unwrap().to_string_lossy().into_owned();
            assert!(p.starts_with(&home), "{p} not under HOME");
            assert!(std::path::Path::new(&p).exists());
        }
    }

    #[test]
    fn shutdown_replies_then_exits() {
        let (reply, exit) = handle(&json!({ "id": 2, "method": "plugin/shutdown" }));
        assert!(reply.is_some() && exit);
    }
}
