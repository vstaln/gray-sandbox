# gray-sandbox

Run bash commands under bubblewrap.

A sidecar plugin for [gray](https://github.com/vstaln/gray). Port of the
policy core of pi's `sandbox/` extension (MIT). The original rebuilt the
bash tool around `@anthropic-ai/sandbox-runtime`; a sidecar can't replace
tools, so `tool/before` on `bash` answers `{"decision":"modify"}` wrapping
the command:

```
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
      [--ro-bind <p> <p>]… [--bind <p> <p>]… \
      --bind <cwd> <cwd> --chdir <cwd> [--unshare-net] \
      -- bash -lc '<command>'
```

Everything is read-only except the session cwd and configured extras;
`--unshare-net` is applied unless `network` is enabled in the config.

## Config

`~/.gray/sandbox/config.json`:

```json
{"enabled": true, "network": false, "extra_ro": [], "extra_rw": []}
```

Defaults: sandbox on, network unshared, no extra binds. `~/` in extra
paths expands to `$HOME`; nonexistent extra paths are skipped so a stale
entry can't break the wrap.

## Commands

- `/sandbox on|off` — enable/disable wrapping
- `/sandbox net on|off` — allow/deny network (`net off` → `--unshare-net`)
- `/sandbox ro <path>` / `/sandbox rw <path>` — extra read-only / writable binds
- `/sandbox status` — show config + bwrap presence

## Safety

- Never wraps a command already invoking `bwrap` or `sudo` (token match,
  basename-aware).
- If `bwrap` isn't on PATH, sends one `host/say` notice per session
  ("bwrap not installed, sandbox off") and allows — needs the `host.say`
  capability; degrades gracefully without it.
- Fail open: any internal error → allow. A broken sandbox must not brick
  bash.

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
