# Architecture

`ttd-mcp` is a Windows-first MCP server for offline WinDbg Time Travel Debugging traces.

The server is split into three layers:

1. Rust MCP server over stdio using the official `rmcp` Rust MCP SDK. This owns MCP protocol transport, tool schemas, session ids, validation, symbol-path settings, and packaging workflow.
2. Safe Rust replay facade. This keeps TTD positions, sessions, cursors, memory reads, modules, threads, and exceptions in serializable Rust types.
3. Native C++ replay bridge. This is a narrow C ABI over Microsoft's C++ TTD Replay API from `Microsoft.TimeTravelDebugging.Apis`.

The C++ bridge exists because the public TTD API is C++-oriented. Rust should not bind directly to TTD C++ vtables, STL helpers, or lifetime rules. The bridge exposes opaque handles and simple POD values.

## Dependencies

Build-time SDK inputs come from NuGet:

- `Microsoft.TimeTravelDebugging.Apis` for headers and import libraries.
- `Microsoft.Debugging.Platform.SymSrv` for Microsoft symbol-server compatible downloads.
- `Microsoft.Debugging.Platform.SrcSrv` for source-server support alongside public symbols.
- `Microsoft.Debugging.Platform.DbgEng` for debugger-platform headers and DLLs when needed later.

Runtime replay requires `TTDReplay.dll` and `TTDReplayCPU.dll`. Microsoft samples acquire these from the WinDbg/TTD MSIX distribution rather than a separate public NuGet package. Use:

```powershell
cargo xtask deps
```

or run [scripts/Get-TtdReplayRuntime.ps1](../scripts/Get-TtdReplayRuntime.ps1) directly.

The native bridge has a CMake project at [native/ttd-replay-bridge/CMakeLists.txt](../native/ttd-replay-bridge/CMakeLists.txt). `cargo xtask native-build` configures it against the restored `Microsoft.TimeTravelDebugging.Apis` package and emits the bridge under `target/native/ttd-replay-bridge`.

## Symbols

The default symbol path is equivalent to:

```text
srv*.ttd-symbol-cache*https://msdl.microsoft.com/download/symbols
```

`cargo xtask deps` stages `dbghelp.dll`, `symsrv.dll`, and `srcsrv.dll` from Microsoft Debugging Platform NuGet packages into `target/symbol-runtime`. Keep this repo-local and process-local; do not set machine-wide `_NT_SYMBOL_PATH` or write debugger registry keys as part of normal server operation.

Callers can provide additional binary paths, symbol paths, and a symbol cache directory when loading a trace. Public symbols are useful for module/function names. Private symbols are needed for richer function signatures and local details.

The Rust facade resolves caller settings into a process-local symbol configuration before opening a trace. That resolved configuration includes the symbol path, image path, cache directory, and symbol runtime directory, and the native bridge open ABI accepts those fields directly.

## Current State

The Rust MCP server uses `rmcp` for stdio MCP protocol handling, and the native bridge boundary is scaffolded, built, and wired for the first native replay slices. The server can advertise tools, validate inputs, load a trace through `ttd_mcp_open_trace`, read `ttd_mcp_trace_info`, enumerate trace-wide threads/modules/exceptions/keyframes, list cursor-local module snapshots, list module and thread lifecycle events, create cursors, get/set cursor positions including TTD thread-scoped seeking, list active cursor threads with runtime PCs, step or trace cursors forward/backward, read compact and x64 scalar/SIMD cursor register/thread state, read bounded guest memory with selectable TTD query policies, query trace-backed memory ranges and provenance-rich memory buffers at a cursor, replay to memory watchpoints, and extract the process command line from PEB process parameters. The next implementation step is to expand callback-backed bounded replay sweeps for call tracing and event collection.
