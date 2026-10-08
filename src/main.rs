//! gray-sandbox — a gray sidecar plugin.
//!
//! With no arguments it speaks gray's NDJSON wire protocol on stdio: one JSON
//! request per stdin line, one reply per stdout line. `gray-sandbox manifest`
//! prints the manifest for humans and `gray account check`.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

fn manifest() -> Value {
    json!({
        "name": "sandbox",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "1.1",
        "tools": [{
            "name": "sandbox_hello",
            "description": "Example tool from the gray-account template: greets `name`. Replace me.",
            "parameters": {
                "type": "object",
                "properties": { "name": { "type": "string", "description": "Who to greet." } },
                "required": ["name"]
            }
        }],
        "commands": ["/sandbox"],
    })
}

/// A tool call. Return `Ok(text)` for the model, `Err(text)` for a tool error.
fn call_tool(name: &str, args: &Value) -> Result<String, String> {
    match name {
        "sandbox_hello" => {
            let who = args.get("name").and_then(Value::as_str).unwrap_or("").trim();
            if who.is_empty() {
                return Err("missing required argument: name".into());
            }
            Ok(format!("hello, {who}!"))
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

/// A slash command typed by the user (`/sandbox …`). `argv` excludes the name.
fn run_command(argv: &[&str]) -> String {
    if argv.is_empty() {
        format!("sandbox {} — edit src/main.rs to make me useful", env!("CARGO_PKG_VERSION"))
    } else {
        format!("sandbox got: {}", argv.join(" "))
    }
}

/// One request → `Some(reply)`, or `None` for notifications. The bool asks
/// the loop to exit after writing the reply.
fn handle(req: &Value) -> (Option<Value>, bool) {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let Some(id) = id else {
        return (None, method == "plugin/shutdown");
    };
    let result = match method {
        "plugin/manifest" => manifest(),
        "tool/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("args").cloned().unwrap_or(Value::Null);
            match call_tool(name, &args) {
                Ok(text) => json!({ "content": text }),
                Err(text) => json!({ "content": text, "is_error": true }),
            }
        }
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
        if let Some(reply) = reply {
            writeln!(stdout, "{reply}")?;
            stdout.flush()?;
        }
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
        handle(&json!({ "id": 1, "method": method, "params": params })).0.unwrap()
    }

    #[test]
    fn manifest_names_the_plugin_and_its_version() {
        let m = call("plugin/manifest", Value::Null)["result"].clone();
        assert_eq!(m["name"], "sandbox");
        assert_eq!(m["version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn tool_call_returns_content() {
        let r = call("tool/call", json!({ "name": "sandbox_hello", "args": { "name": "gray" } }));
        assert_eq!(r["result"]["content"], "hello, gray!");
        assert!(r["result"].get("is_error").is_none());
    }

    #[test]
    fn tool_errors_are_flagged() {
        let r = call("tool/call", json!({ "name": "sandbox_hello", "args": {} }));
        assert_eq!(r["result"]["is_error"], true);
    }

    #[test]
    fn unknown_methods_are_method_not_found() {
        assert_eq!(call("nope", Value::Null)["error"]["code"], -32601);
    }

    #[test]
    fn shutdown_replies_then_exits_and_notifications_are_silent() {
        let (reply, exit) = handle(&json!({ "id": 2, "method": "plugin/shutdown" }));
        assert!(reply.is_some() && exit);
        let (reply, exit) = handle(&json!({ "method": "plugin/shutdown" }));
        assert!(reply.is_none() && exit);
    }
}
