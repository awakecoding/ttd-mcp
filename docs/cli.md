# CLI guide

`windbg-tool.exe` can act as a local discovery tool, a daemon-backed TTD client, a DbgEng helper, and a WinDbg launcher/updater.

## How the CLI is organized

- **Discovery commands** do not require the daemon: `discover`, `recipes`, `tools`, `schema`, `trace-list`, `symbols inspect`
- **Replay commands** usually talk to the local daemon and operate on a `session_id` and `cursor_id`
- **Platform helper commands** cover DbgEng, remote debugging recipes, live-launch probing, and WinDbg installation

## Common replay workflow

Start or reuse the local daemon:

```powershell
target\debug\windbg-tool.exe daemon ensure
```

Open a trace and create a cursor in one step:

```powershell
target\debug\windbg-tool.exe open C:\path\to\trace.run --binary-path C:\path\to\binary.exe
```

Rediscover active sessions and cursors later:

```powershell
target\debug\windbg-tool.exe sessions
```

Use the returned handles with analysis commands:

```powershell
target\debug\windbg-tool.exe info --session 1
target\debug\windbg-tool.exe context snapshot --session 1 --cursor 1
target\debug\windbg-tool.exe position set --session 1 --cursor 1 --position 50
target\debug\windbg-tool.exe registers --session 1 --cursor 1
target\debug\windbg-tool.exe disasm --session 1 --cursor 1
target\debug\windbg-tool.exe memory strings --session 1 --cursor 1 --address 0x12345678 --size 256 --encoding both
```

`open` is the preferred starting point because it loads the trace, creates a cursor, and optionally seeks to a position in one response.

## Session and cursor basics

- `session_id` identifies the loaded trace
- `cursor_id` identifies a replay cursor inside that trace
- Many commands accept `-s` for `--session` and `-c` for `--cursor`
- `position set` accepts either a structured position, a WinDbg-style `HEX:HEX` string, or a percentage from `0` to `100`

## Output shaping

CLI output is JSON by default. These flags make it easier to script:

- `--compact` for single-line JSON
- `--field <dot.path>` to extract one field
- `--raw` to print scalar values without JSON quotes

Example:

```powershell
target\debug\windbg-tool.exe --field session_id --raw open C:\path\to\trace.run
target\debug\windbg-tool.exe --compact registers --session 1 --cursor 1
```

## Command groups worth learning first

| Goal | Commands |
| --- | --- |
| Discover capabilities | `discover`, `recipes`, `tools`, `schema <tool>` |
| Manage daemon/session state | `daemon ensure`, `daemon status`, `sessions`, `open`, `load`, `close`, `info` |
| Move through a trace | `cursor create`, `position get`, `position set`, `step`, `replay to`, `replay watch-memory`, `sweep watch-memory` |
| Inspect trace metadata | `threads`, `modules`, `exceptions`, `keyframes`, `timeline events`, `module info`, `module audit` |
| Inspect runtime state | `registers`, `register-context`, `active-threads`, `command-line`, `architecture state` |
| Inspect code and memory | `disasm`, `memory read`, `memory dump`, `memory strings`, `memory dps`, `memory classify`, `memory chase`, `object vtable` |
| Symbol and source triage | `symbols diagnose`, `symbols inspect`, `symbols exports`, `symbols nearest`, `source resolve` |
| WinDbg, live, dump, and remote helpers | `remote explain`, `remote server-command`, `remote connect-command`, `dbgeng server`, `live capabilities`, `dump create`, `dump open`, `dump inspect`, `target dump`, `windbg status` |

## Useful non-replay commands

These are good starting points even before you have a trace open:

```powershell
target\debug\windbg-tool.exe discover
target\debug\windbg-tool.exe recipes
target\debug\windbg-tool.exe remote explain
target\debug\windbg-tool.exe symbols inspect C:\Windows\System32\notepad.exe
target\debug\windbg-tool.exe windbg status
```

## Working with multiple workspaces

Use `--pipe \\.\pipe\windbg-tool-custom` or set `WINDBG_TOOL_PIPE` to isolate concurrent daemon instances. The legacy `TTD_MCP_PIPE` variable is also honored.

## Next docs

- For MCP setup and tool flow, see [mcp.md](mcp.md)
- For build, native runtime, and local test details, see [development.md](development.md)
