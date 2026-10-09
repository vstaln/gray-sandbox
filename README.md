<p align="center"><img src="assets/gray-logo.svg" width="120" alt="gray logo"></p>
<h1 align="center">gray-sandbox</h1>
<p align="center">OS-level sandboxing for bash commands — bubblewrap filesystem isolation with a filtering network proxy, modeled on Anthropic's <code>sandbox-runtime</code>.</p>
<p align="center">
  <a href="https://github.com/vstaln/gray-sandbox/blob/main/LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="gray plugin" src="https://img.shields.io/badge/gray-plugin-7aa2f7.svg">
  <img alt="rust" src="https://img.shields.io/badge/built%20with-rust-orange.svg">
</p>

## What it does

Every `bash` tool call is rewritten to run inside a bubblewrap sandbox:

```
bwrap --die-with-parent --ro-bind / / --dev /dev --proc /proc \
      --tmpfs /tmp [ro/rw binds] --bind <cwd> <cwd> \
      [deny shadows] --chdir <cwd> [--unshare-net] \
      --setenv GRAY_SANDBOX nested -- bash -lc '<command>'
```

- **Filesystem** — root is read-only; the session cwd and dev caches
  (`~/.cache .cargo .rustup .npm .bun .deno .local .gray .config/pip go
  .m2 .gradle .venv .poetry .gitconfig`) are writable. Credential paths
  (`~/.aws ~/.gnupg ~/.netrc ~/.docker`) are shadowed — dirs get a tmpfs,
  files get a `/dev/null` bind. `deny_write` globs (default `.env`,
  `.env.*`, `*.pem`, `*.key`) shadow matching cwd entries too.
- **Network** — three modes:
  - `on` (default) — full egress
  - `off` — `--unshare-net`, loopback only
  - `allowlist` — still `--unshare-net`, but the child sees
    `http_proxy=http://127.0.0.1:18080` bridged by **socat** to a unix
    socket where the sidecar runs a filtering CONNECT proxy checking
    `allowed_domains`/`denied_domains` (exact or `*.suffix`). Fails
    **closed** when socat isn't installed.
- **Nesting** — the wrapper sets `GRAY_SANDBOX=nested`; every process
  inside (incl. `gray -p` workers and subagents) inherits it and skips
  wrapping — they're already confined by the outer sandbox.
  `GRAY_SANDBOX=off` is the manual escape hatch.
- **Passthrough** — commands invoking `bwrap`, `sudo`, `docker`,
  `podman`, `socat`, `systemd-run`, … are never wrapped (configurable).

## Commands

| command | effect |
|---|---|
| `/sandbox` or `status` | show mode, lists, bwrap/socat presence |
| `/sandbox on` / `off` | enable/disable the whole sandbox |
| `/sandbox net on` / `off` / `allowlist` | network mode |
| `/sandbox allow <domain>` / `deny <domain>` | add to allow/deny list (adding a domain switches net to `allowlist`) |
| `/sandbox ro <path>` / `rw <path>` | extra bind |
| `/sandbox deny-read <path>` | shadow a path (`~` expands) |
| `/sandbox deny-write <glob>` | shadow cwd files matching a glob |

## Config

`~/.gray/sandbox/config.json` — flat keys or the upstream nested shape,
both spellings (`allowed_domains`/`allowedDomains`) accepted:

```json
{
  "enabled": true,
  "network": {
    "mode": "allowlist",
    "allowed_domains": ["github.com", "*.github.com", "*.npmjs.org"],
    "denied_domains": ["pastebin.com"]
  },
  "filesystem": {
    "deny_read": ["~/.aws", "~/.gnupg", "~/.netrc", "~/.docker"],
    "allow_write": ["~/src"],
    "deny_write": [".env", ".env.*", "*.pem", "*.key"]
  },
  "extra_ro": [],
  "extra_rw": [],
  "passthrough": ["bwrap", "sudo", "docker", "podman"]
}
```

`"network": true/false` and `"on"|"off"` strings are also accepted
(legacy compat).

## Dependencies

- `bwrap` (bubblewrap) — required; plugin warns once and passes
  commands through when absent
- `socat` — required only for `net allowlist` (in-sandbox bridge);
  without it allowlist mode fails closed

## Differences from sandbox-runtime

- `~/.ssh` is **not** deny-read by default (git-over-ssh pushes need it)
  — add it with `/sandbox deny-read ~/.ssh` if you don't.
- `deny_write` shadows only *existing* cwd entries at wrap time —
  a file created fresh in a writable dir can't be pre-mounted.
- The allowlist filter only sees traffic honoring `http_proxy`
  (curl/npm/pip/cargo do; raw sockets and SSH don't — SSH just fails
  inside allowlist mode).
- Linux only; macOS seatbelt is not implemented.

## Install

```bash
cd gray-sandbox && cargo build --release
install -m755 target/release/gray-sandbox ~/.local/bin/gray-sandbox
```

---

Part of the [gray](https://gray.alignment.id) plugin ecosystem.
