# ttd-mcp

`ttd-mcp` is a Rust MCP server for offline WinDbg Time Travel Debugging traces. The goal is to load saved `.run` or `.ttd` traces, replay them without attaching to a live process, and expose useful debugging operations to MCP clients.

The project is intentionally Windows-first. TTD replay uses Microsoft's TTD Replay Engine APIs, which are distributed through the `Microsoft.TimeTravelDebugging.Apis` NuGet package and the WinDbg/TTD runtime distribution.

## Current Status

This repository contains the first implementation slice:

- A stdio MCP server in Rust.
- Tool schemas for trace loading, metadata, cursors, seeking, registers, memory, and watchpoints.
- A safe Rust replay facade with TTD position parsing and symbol-path handling.
- A C ABI C++ bridge scaffold for the TTD Replay API.
- Dependency/runtime acquisition scripts and architecture docs.

The native bridge now builds with CMake and the Rust facade uses it when available for trace loading, trace metadata, thread/module/exception enumeration, cursor creation, and position get/set. Registers, memory reads, stepping, and watchpoints still need native-backed implementations.

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

## Trace Privacy

TTD trace files can contain memory, file paths, registry data, and other sensitive process state from the recorded machine. Treat `.run` and `.idx` files as sensitive artifacts and avoid committing them.

## Local Ping Trace Tests

The first local end-to-end fixture is expected at `traces/ping`:

```text
traces/ping/ping01.run
traces/ping/ping01.idx
traces/ping/ping.exe
```

These artifacts are local-only and ignored by git. The Rust integration tests skip cleanly when the fixture is absent. Run strict local replay checks with:

```powershell
$env:TTD_TEST_TRACE = "D:\dev\ttd-mcp\traces\ping\ping01.run"
$env:TTD_RUNTIME_DIR = "D:\dev\ttd-mcp\target\ttd-runtime"
$env:TTD_MCP_EXPECT_NATIVE_REPLAY = "1"
cargo test -p ttd-mcp --test ping_trace
```
