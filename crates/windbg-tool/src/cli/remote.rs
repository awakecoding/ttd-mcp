use anyhow::bail;
use serde_json::{json, Value};

use super::{RemoteCommand, RemoteConnectCommandArgs, RemoteKind, RemoteServerCommandArgs};

pub(super) fn remote_command_value(command: RemoteCommand) -> anyhow::Result<Value> {
    match command {
        RemoteCommand::Explain(args) => {
            let workflows = remote_workflows();
            let Some(kind) = args.kind else {
                return Ok(json!({
                    "workflows": workflows,
                    "default": "dbgsrv",
                    "recipes": ["windbg-tool recipes remote-debugging"],
                }));
            };
            Ok(json!({
                "workflow": remote_workflow(kind),
                "recipes": ["windbg-tool recipes remote-debugging"],
            }))
        }
        RemoteCommand::ServerCommand(args) => {
            if matches!(args.kind, RemoteKind::Ntsd)
                && args.pid.is_some()
                && args.executable.is_some()
            {
                bail!(
                    "remote server-command --kind ntsd accepts either --pid or --executable, not both"
                )
            }
            Ok(json!({
                "side": "target",
                "workflow": remote_workflow(args.kind),
                "command": remote_server_command(&args),
                "notes": remote_server_notes(&args),
            }))
        }
        RemoteCommand::ConnectCommand(args) => Ok(json!({
            "side": "host",
            "workflow": remote_workflow(args.kind),
            "command": remote_connect_command(&args),
            "notes": remote_connect_notes(&args),
        })),
    }
}

fn remote_workflows() -> Value {
    json!([
        remote_workflow(RemoteKind::Dbgsrv),
        remote_workflow(RemoteKind::Ntsd)
    ])
}

fn remote_workflow(kind: RemoteKind) -> Value {
    match kind {
        RemoteKind::Dbgsrv => json!({
            "kind": "dbgsrv",
            "summary": "DbgEng process server: debugger brains, symbols, and extensions stay on the host.",
            "use_when": [
                "target should stay lightweight",
                "host owns symbol/source paths and extensions",
                "host should launch or attach through -premote"
            ],
            "target_side": "windbg-tool dbgeng server --transport tcp:port=5005",
            "host_side": "windbg-tool windbg run -- -premote tcp:port=5005,server=<target>"
        }),
        RemoteKind::Ntsd => json!({
            "kind": "ntsd",
            "summary": "NTSD/CDB remote session: debugger brains, symbols, and extensions run on the target.",
            "use_when": [
                "latency is high and command execution should be target-local",
                "target has the necessary symbols/extensions",
                "a preexisting debugger session should be exposed remotely"
            ],
            "target_side": "ntsd -server tcp:port=5005 -p <pid>",
            "host_side": "windbg-tool windbg run -- -remote tcp:port=5005,server=<target>"
        }),
    }
}

fn remote_server_command(args: &RemoteServerCommandArgs) -> Vec<String> {
    match args.kind {
        RemoteKind::Dbgsrv => vec![
            "windbg-tool".to_string(),
            "dbgeng".to_string(),
            "server".to_string(),
            "--transport".to_string(),
            args.transport.clone(),
        ],
        RemoteKind::Ntsd => {
            let mut command = vec![
                "ntsd".to_string(),
                "-server".to_string(),
                args.transport.clone(),
            ];
            if let Some(pid) = args.pid {
                command.push("-p".to_string());
                command.push(pid.to_string());
            } else if let Some(executable) = &args.executable {
                command.push(executable.clone());
            } else {
                command.push("-p".to_string());
                command.push("<pid>".to_string());
            }
            command
        }
    }
}

fn remote_server_notes(args: &RemoteServerCommandArgs) -> Value {
    match args.kind {
        RemoteKind::Dbgsrv => json!([
            "Run on the target machine.",
            "The command blocks until the DbgEng process server exits.",
            "Use remote connect-command --kind dbgsrv on the host to generate the WinDbg -premote command."
        ]),
        RemoteKind::Ntsd => json!([
            "Run on the target machine with NTSD or CDB available.",
            "Symbols and extensions are resolved by the target-side debugger process.",
            "Use remote connect-command --kind ntsd on the host to generate the WinDbg -remote command."
        ]),
    }
}

fn remote_connect_command(args: &RemoteConnectCommandArgs) -> Vec<String> {
    let remote = format!("{},server={}", args.transport, args.server);
    match args.kind {
        RemoteKind::Dbgsrv => vec![
            "windbg-tool".to_string(),
            "windbg".to_string(),
            "run".to_string(),
            "--".to_string(),
            "-premote".to_string(),
            remote,
        ],
        RemoteKind::Ntsd => vec![
            "windbg-tool".to_string(),
            "windbg".to_string(),
            "run".to_string(),
            "--".to_string(),
            "-remote".to_string(),
            remote,
        ],
    }
}

fn remote_connect_notes(args: &RemoteConnectCommandArgs) -> Value {
    match args.kind {
        RemoteKind::Dbgsrv => json!([
            "Run on the host machine.",
            "This connects WinDbg to a DbgSrv process server; launch/attach decisions happen from the host.",
            "Append additional WinDbg launch/attach arguments after the generated -premote transport if needed."
        ]),
        RemoteKind::Ntsd => json!([
            "Run on the host machine.",
            "This connects WinDbg to an existing target-side NTSD/CDB -server session.",
            "Do not use -premote for NTSD/CDB -server sessions."
        ]),
    }
}
