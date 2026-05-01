# ttd-mcp

`ttd-mcp` is a Rust MCP server for offline WinDbg Time Travel Debugging traces. The goal is to load saved `.run` or `.ttd` traces, replay them without attaching to a live process, and expose useful debugging operations to MCP clients.

The project is intentionally Windows-first. TTD replay uses Microsoft's TTD Replay Engine APIs, which are distributed through the `Microsoft.TimeTravelDebugging.Apis` NuGet package and the WinDbg/TTD runtime distribution.

## Current Status

This repository contains the first implementation slice:

- A stdio MCP server in Rust using the official `rmcp` Rust MCP SDK.
- Tool schemas for trace loading, metadata, cursors, seeking, registers, memory, and watchpoints.
- A safe Rust replay facade with TTD position parsing and symbol-path handling.
- A C ABI C++ bridge scaffold for the TTD Replay API.
- Dependency/runtime acquisition scripts and architecture docs.

The native bridge now builds with CMake and the Rust facade uses it when available for trace loading, trace metadata, thread/module/exception/keyframe enumeration, module and thread lifecycle event timelines, cursor creation, position get/set, active-thread snapshots, forward/backward stepping, compact and x64 scalar/SIMD cursor register/thread state, bounded memory reads, trace-backed memory range and buffer provenance queries, memory watchpoint replay, and trace-derived command-line extraction from PEB process parameters.

## Build

```powershell
cargo build
cargo test --workspace
```

## Dependency Setup

Run this from a Visual Studio Developer PowerShell or another shell with `nuget`, `cmake`, `msbuild`, and `powershell` available:

```powershell
cargo xtask doctor
cargo xtask deps
cargo xtask native-build
```

`cargo xtask deps` restores native NuGet packages into `target/nuget`, stages `dbghelp.dll`, `symsrv.dll`, and `srcsrv.dll` into `target/symbol-runtime`, and downloads `TTDReplay.dll` plus `TTDReplayCPU.dll` into `target/ttd-runtime`.

`cargo xtask native-build` configures and builds the C++ bridge with CMake under `target/native/ttd-replay-bridge`. Run it from an MSVC developer environment so CMake can find the Visual C++ toolchain.

To verify the packaged MCP server over stdio, run:

```powershell
cargo xtask mcp-smoke
```

This builds `ttd-mcp`, prepares `target/package`, starts `target/package/ttd-mcp.exe`, runs the MCP initialize and tools/list flow, and loads the local ping trace when `traces/ping/ping01.run` is available.

## Symbols

Symbol support is configured per trace session. The default symbol path is:

```text
srv*.ttd-symbol-cache*https://msdl.microsoft.com/download/symbols
```

The server stages DbgHelp/SymSrv/SrcSrv from Microsoft Debugging Platform NuGet packages into `target/symbol-runtime`. It does not set machine-wide `_NT_SYMBOL_PATH` or write debugger registry keys; callers pass binary paths, symbol paths, and cache settings through `ttd_load_trace`.

`ttd_load_trace` returns both the legacy `symbol_path` string and a `symbols` object with the resolved symbol path, image path, cache directory, symbol runtime directory, and binary path count. The native bridge ABI accepts the same resolved fields so the replay backend can initialize symbol support without relying on machine-wide debugger settings.

## MCP Configuration

After building, configure your MCP client to launch the server over stdio:

```json
{
  "servers": {
    "ttd-mcp": {
      "command": "d:/dev/ttd-mcp/target/debug/ttd-mcp.exe",
      "args": []
    }
  }
}
```

## MCP Tools

Tools are exposed through the normal MCP `tools/list` and `tools/call` flow. Tool results are returned as JSON text content. Tool failures are reported as MCP tool results with `isError: true`, so clients can distinguish tool errors from JSON-RPC protocol errors.

Most replay operations use two handles:

- `session_id`: returned by `ttd_load_trace`.
- `cursor_id`: returned by `ttd_cursor_create`. A session may have multiple independent cursors.

Positions are serialized as objects with decimal `sequence` and `steps` fields:

```json
{ "sequence": 3171775, "steps": 26 }
```

For `ttd_position_set`, the `position` argument may be one of:

- A position object, such as `{ "sequence": 3171775, "steps": 26 }`.
- A WinDbg-style hex string, such as `"3065BF:1A"`.
- A percentage number from `0` to `100`, which is resolved against the trace lifetime by sequence.

### Session Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `ttd_load_trace` | `trace_path`; optional `symbols` object | Opens a `.run` or `.ttd` trace and returns `session_id`, trace metadata, the resolved `symbol_path`, and resolved symbol settings. If the native bridge or runtime DLLs are unavailable, it creates a placeholder session with a warning. |
| `ttd_close_trace` | `session_id` | Closes the trace session and releases native replay resources. |
| `ttd_trace_info` | `session_id` | Returns trace path, backend name, index status, process/PEB details when available, trace lifetime, architecture, and event/list counts. |

The optional `symbols` object accepted by `ttd_load_trace` has these fields:

```json
{
  "binary_paths": ["traces/ping/ping.exe", "C:/Windows/System32"],
  "symbol_paths": ["srv*C:/symbols*https://msdl.microsoft.com/download/symbols"],
  "symcache_dir": ".ttd-symbol-cache"
}
```

If `symbol_paths` does not already include the Microsoft public symbol server, the server appends `srv*<symcache_dir>*https://msdl.microsoft.com/download/symbols` automatically. `binary_paths` are joined into the native image path so replay and later symbol features can find binaries that match the trace.

### Trace Metadata Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `ttd_list_threads` | `session_id` | Lists trace threads with unique TTD thread id, OS thread id, lifetime positions, and active-time positions when available. Requires the native replay backend for non-empty results. |
| `ttd_list_modules` | `session_id` | Lists module instances with name, path, base address, size, load position, and unload position when available. Requires the native replay backend for module data. |
| `ttd_list_keyframes` | `session_id` | Lists replay keyframe positions captured in the trace. Requires the native replay backend for non-empty results. |
| `ttd_module_events` | `session_id` | Lists module load and unload events with event position and module identity. Requires the native replay backend for non-empty results. |
| `ttd_thread_events` | `session_id` | Lists thread create and terminate events with event position and thread identity/lifetime data. Requires the native replay backend for non-empty results. |
| `ttd_list_exceptions` | `session_id` | Lists exception events with position, thread unique id, exception code/flags, program counter, record address, and parameters. Requires the native replay backend for non-empty results. |

### Cursor And Navigation Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `ttd_cursor_create` | `session_id` | Creates an independent replay cursor and returns `cursor_id` plus its starting position. |
| `ttd_position_get` | `session_id`, `cursor_id` | Returns the current cursor position. |
| `ttd_position_set` | `session_id`, `cursor_id`, `position` | Moves the cursor to a position object, `HEX:HEX` string, or approximate lifetime percentage. |
| `ttd_step` | `session_id`, `cursor_id`; optional `direction`, `kind`, `count` | Replays the cursor forward or backward and returns the new position, previous position, requested count, executed step/instruction counts, and stop reason. Requires the native replay backend. |
| `ttd_active_threads` | `session_id`, `cursor_id` | Lists threads active at the cursor position with per-thread positions, PC/SP/FP/TEB state, and module/RVA coordinates for each runtime PC when available. Requires the native replay backend. |

`ttd_step` defaults to:

```json
{
  "direction": "forward",
  "kind": "step",
  "count": 1
}
```

`direction` may be `"forward"` or `"backward"`. `kind` may be `"step"` or `"trace"`; `step` currently uses TTD replay's current-thread flag, while `trace` allows replay across the normal trace execution flow. `count` must be between `1` and `10000`.

### State And Memory Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `ttd_registers` | `session_id`, `cursor_id` | Returns compact cursor state: position, previous position, current thread ids, TEB address, program counter, stack pointer, frame pointer, and basic return value. Requires the native replay backend. |
| `ttd_register_context` | `session_id`, `cursor_id`; optional `thread_id` | Returns x64 register context from TTD `GetCrossPlatformContext` and `GetAvxExtendedContext`, including control, segment, debug, general-purpose, XMM/YMM vector registers, branch/exception RIP fields, current thread identity, TEB, and module/RVA coordinates for RIP. Requires the native replay backend. |
| `ttd_command_line` | `session_id`, `cursor_id` | Reads the process command line by following the PEB process-parameters pointers at the cursor position. Requires x64 PEB layout assumptions and the native replay backend. |
| `ttd_read_memory` | `session_id`, `cursor_id`, `address`, `size` | Reads guest memory at the cursor position and returns the requested address/size, actual address, byte count, completeness flag, and lowercase hex data. Requires the native replay backend. |
| `ttd_memory_range` | `session_id`, `cursor_id`, `address`; optional `max_bytes` | Queries the trace-backed contiguous memory range containing or following a guest address, returning the range address, source sequence, available byte count, bounded hex bytes, and module/RVA coordinates when available. Requires the native replay backend. |
| `ttd_memory_buffer` | `session_id`, `cursor_id`, `address`, `size`; optional `max_ranges` | Reads guest memory at the cursor position and returns lowercase hex data plus per-subrange source sequences, buffer offsets, and module/RVA coordinates for correlating runtime bytes with static analysis tools. Requires the native replay backend. |
| `ttd_memory_watchpoint` | `session_id`, `cursor_id`, `address`, `size`, `access`, `direction` | Finds the previous or next read/write/execute access to a guest memory range, moves the cursor to the replay stop position, and returns hit details when found. Requires the native replay backend. |

`ttd_register_context` defaults to the cursor's current thread; pass an active OS `thread_id` from `ttd_active_threads` to inspect another live thread at the same cursor position. XMM values are 16-byte little-endian hex strings, and YMM values are reconstructed as 32-byte little-endian hex strings from the lower XMM state plus the AVX high half. `ttd_read_memory` and `ttd_memory_buffer` require `address` to be non-zero and `size` to be between `1` and `65536` bytes. `ttd_memory_buffer` defaults to `64` source ranges and accepts up to `1024`. `ttd_memory_range` requires `address` to be non-zero and limits `max_bytes` to `65536`; set `max_bytes` to `0` to request provenance without returning bytes. `ttd_memory_watchpoint` requires a non-zero `address` and non-zero `size`, accepts `access` values `"read"`, `"write"`, `"execute"`, or `"read_write"`, and accepts `direction` values `"previous"` or `"next"`. A successful watchpoint response with `"found": false` means replay reached a trace boundary or other stop before a matching access; it is not a tool error.

### Example Tool Calls

Load a trace with a matching binary next to it:

```json
{
  "name": "ttd_load_trace",
  "arguments": {
    "trace_path": "traces/ping/ping01.run",
    "symbols": {
      "binary_paths": ["traces/ping/ping.exe"]
    }
  }
}
```

Create a cursor, move near the middle of the trace, and step one instruction on the current thread:

```json
{ "name": "ttd_cursor_create", "arguments": { "session_id": 1 } }
{ "name": "ttd_position_set", "arguments": { "session_id": 1, "cursor_id": 1, "position": 50 } }
{ "name": "ttd_step", "arguments": { "session_id": 1, "cursor_id": 1, "direction": "forward", "kind": "step", "count": 1 } }
```

Read 64 bytes from the PEB address reported by `ttd_trace_info`:

```json
{
  "name": "ttd_read_memory",
  "arguments": {
    "session_id": 1,
    "cursor_id": 1,
    "address": 140703128616960,
    "size": 64
  }
}
```

Search backward for a read of a known memory range:

```json
{
  "name": "ttd_memory_watchpoint",
  "arguments": {
    "session_id": 1,
    "cursor_id": 1,
    "address": 140703128616960,
    "size": 16,
    "access": "read",
    "direction": "previous"
  }
}
```

## Sample Ping Trace Prompts

Once the sample fixture is extracted, an MCP client can use the local trace and matching binary:

```text
traces/ping/ping01.run
traces/ping/ping.exe
```

These prompts are written for an assistant that has this MCP server configured as `ttd-mcp`. They intentionally ask for raw trace facts, modules, positions, registers, memory, command-line data, and memory watchpoint replay, which are supported today. Full symbol lookup, source lookup, and stack unwinding are planned but not implemented yet.

### Load And Summarize

```text
Use the ttd-mcp server to load traces/ping/ping01.run with traces/ping/ping.exe as the matching binary path. Summarize the trace backend, process id, lifetime start/end positions, thread count, module count, exception count, and whether native replay is active.
```

Expected tool flow: `ttd_load_trace`, then `ttd_trace_info`.

### Confirm The Recorded Command

```text
Load the sample ping TTD trace, create a replay cursor, and read the recorded process command line. Tell me exactly what ping.exe command was captured.
```

Expected tool flow: `ttd_load_trace`, `ttd_cursor_create`, then `ttd_command_line`.

### Inspect Loaded Modules

```text
Open traces/ping/ping01.run with traces/ping/ping.exe as the binary path, list the captured modules, and tell me whether ping.exe appears in the module list. Include its base address, size, load position, and path if available.
```

Expected tool flow: `ttd_load_trace`, then `ttd_list_modules`.

### Check Threads And Exceptions

```text
Use the ping trace to list all captured threads and exceptions. Summarize the OS thread ids, lifetime ranges, active ranges, exception codes, exception positions, and program counters. If there are no exceptions, say that directly.
```

Expected tool flow: `ttd_load_trace`, `ttd_list_threads`, then `ttd_list_exceptions`.

### Seek And Step

```text
Load the sample ping trace, create a cursor, move it to 50 percent through the trace, show the current position and compact register state, then step forward one current-thread step. Report the old position, new position, stop reason, program counter, stack pointer, and current thread id.
```

Expected tool flow: `ttd_load_trace`, `ttd_cursor_create`, `ttd_position_set`, `ttd_registers`, `ttd_step`, then `ttd_registers` again.

### Compare Start, Middle, And End State

```text
For traces/ping/ping01.run, create one cursor and compare compact register state at 0 percent, 50 percent, and 100 percent through the trace. For each point, include the resolved position, thread id, program counter, stack pointer, frame pointer, and TEB address.
```

Expected tool flow: `ttd_load_trace`, `ttd_cursor_create`, repeated `ttd_position_set` and `ttd_registers` calls.

### Read Process Memory Near The PEB

```text
Load the sample ping trace and read trace info to find the PEB address. Create a cursor, then read 64 bytes at the PEB address. Show the address actually read, byte count, completeness flag, and the hex bytes. Do not interpret fields beyond what the current tools can prove.
```

Expected tool flow: `ttd_load_trace`, `ttd_trace_info`, `ttd_cursor_create`, then `ttd_read_memory`.

### Find A Previous Command-Line Buffer Read

```text
Load the sample ping trace, create a cursor, read the recorded process command line, move the cursor to the end of the trace, then search backward for a read of the command-line buffer address. Report whether a hit was found, the stop position, matched address and size, matched access type, program counter, and current thread id.
```

Expected tool flow: `ttd_load_trace`, `ttd_cursor_create`, `ttd_command_line`, `ttd_position_set`, then `ttd_memory_watchpoint`.

### Build A Compact Trace Inventory

```text
Use ttd-mcp to build a compact inventory of the ping TTD trace: trace metadata, command line, thread count with thread ids, module count with the first 10 module names, exception count, and current cursor register state at the trace midpoint.
```

Expected tool flow: `ttd_load_trace`, `ttd_trace_info`, `ttd_cursor_create`, `ttd_command_line`, `ttd_list_threads`, `ttd_list_modules`, `ttd_list_exceptions`, `ttd_position_set`, and `ttd_registers`.

### Validate Native Replay Availability

```text
Load traces/ping/ping01.run through ttd-mcp and check whether the backend is ttd-replay-native. If it is not native, explain the warning from the trace info and stop before asking for registers, memory, command-line, or stepping.
```

Expected tool flow: `ttd_load_trace`, then `ttd_trace_info`.

## Trace Privacy

TTD trace files can contain memory, file paths, registry data, and other sensitive process state from the recorded machine. Treat `.run` and `.idx` files as sensitive artifacts and avoid committing them.

## Local Ping Trace Tests

The committed sample fixture is `traces/ping.7z`. The extracted `traces/ping` directory is ignored by git because it contains large and sensitive replay artifacts. The integration tests automatically extract the archive into `traces/` when the extracted fixture is missing and `7z` or `7zz` is available on `PATH`. If 7-Zip is installed somewhere else, set `TTD_TEST_7Z` to the executable path.

After extraction, the fixture layout is:

```text
traces/ping/ping01.run
traces/ping/ping01.idx
traces/ping/ping.exe
```

The extracted artifacts are local-only and ignored by git. The Rust integration tests skip cleanly when neither the extracted fixture nor a usable archive extractor is available. Run strict local replay checks with:

```powershell
$env:TTD_RUNTIME_DIR = "D:\dev\ttd-mcp\target\ttd-runtime"
$env:TTD_MCP_EXPECT_NATIVE_REPLAY = "1"
cargo test -p ttd-mcp --test ping_trace
```

To force a custom trace instead of the committed archive fixture, set `TTD_TEST_TRACE` to a `.run` file path.
