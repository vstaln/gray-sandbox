<p align="center">
  <img src="assets/gray-logo.svg" alt="gray" width="96">
</p>
<h1 align="center">gray-sandbox</h1>
<p align="center">Run bash commands under a configurable bubblewrap sandbox.</p>
<p align="center">
  <a href="https://github.com/vstaln/gray-sandbox/blob/main/LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="gray plugin" src="https://img.shields.io/badge/gray-plugin-7aa2f7.svg">
  <img alt="rust" src="https://img.shields.io/badge/built%20with-rust-orange.svg">
</p>

Wrap `bash` tool calls in `bwrap` so commands run with a read-only system
view and controlled writable paths.

A sidecar cannot replace the built-in bash tool, so `tool/before` answers
`{"decision":"modify"}` and rewrites the command to:

```sh
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp       [--ro-bind <p> <p>]… [--bind <p> <p>]…       --bind <cwd> <cwd> --chdir <cwd> [--unshare-net]       -- bash -lc '<command>'
```

Everything is read-only except the session cwd and configured extras.
`--unshare-net` is applied unless networking is enabled in the config.

## Config

`~/.gray/sandbox/config.json`:

```json
{"enabled": true, "network": false, "extra_ro": [], "extra_rw": []}
```

Defaults: sandbox on, network unshared, no extra binds. `~/` in extra paths
expands to `$HOME`; nonexistent extra paths are skipped so stale entries do
not break wrapping.

## Commands

- `/sandbox on|off` — enable or disable wrapping
- `/sandbox net on|off` — allow or deny network (`net off` → `--unshare-net`)
- `/sandbox ro <path>` / `/sandbox rw <path>` — add read-only or writable binds
- `/sandbox status` — show config and `bwrap` availability

## Safety

- Never wraps a command already invoking `bwrap` or `sudo` (token match,
  basename-aware).
- If `bwrap` is not on `PATH`, sends one `host/say` notice per session and
  allows the command. The notice needs the `host.say` capability; the plugin
  degrades gracefully without it.
- Fails open: any internal error allows the command. A broken sandbox must
  not brick bash.

## Wire

`plugin/manifest`, `tool/before`, `command/run`, `plugin/shutdown`, plus
outgoing `host/say` requests (string ids; responses are consumed, never
replied to). Protocol 2.0, hook `tool/before`, capability `host.say`.

## Install

```sh
gray plugin install sandbox
gray plugin capabilities sandbox --all   # grant host.say for the notice
```

## Develop

```sh
cargo test
gray account check      # entry point + manifest handshake
gray account publish    # check → build → release → publish to the gray registry
```

Bump `version` in `Cargo.toml` before each `publish`; the registry refuses to
republish a version.

---
Part of the [gray](https://github.com/vstaln/gray) plugin ecosystem —
the open-source AI agent harness. <https://gray.alignment.id>
