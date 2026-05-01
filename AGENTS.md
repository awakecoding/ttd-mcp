# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Purpose

`ttd-mcp` is a Windows-first Rust MCP server for offline WinDbg Time Travel Debugging traces. The goal is to load saved `.run` or `.ttd` traces, replay them without a live process, and expose useful debugging operations through MCP tools.

This project must use the Time Travel Debugging replay APIs, not the regular live-debugging `cdb` or DbgEng attach flow. DbgEng-related packages can be useful for symbols and debugger-platform support, but core replay should go through the TTD Replay API.

## Current Architecture

- Rust workspace root: `Cargo.toml`.
- MCP binary crate: `crates/ttd-mcp`.
- Developer workflow crate: `xtask`.
- Native C++ bridge scaffold: `native/ttd-replay-bridge`.
- Runtime/dependency helper script: `scripts/Get-TtdReplayRuntime.ps1`.
- Architecture notes: `docs/architecture.md`.

The intended layering is:

1. Rust MCP server over stdio using the official `rmcp` Rust MCP SDK, plus tool schemas, validation, session ids, and serialization.
2. Safe Rust replay facade for traces, cursors, positions, modules, threads, exceptions, registers, memory reads, and watchpoints.
3. Narrow C ABI C++ bridge over Microsoft's C++ TTD Replay API.

Do not bind Rust directly to TTD C++ vtables, STL helper types, or C++ ownership rules. Keep the native bridge as a small C ABI with opaque handles and plain data structs.

## Current Implementation State

The Rust MCP server uses `rmcp` for stdio MCP protocol handling, advertises tools, and can use the native bridge for trace loading, trace metadata, thread/module/exception enumeration, cursor creation, position get/set, stepping/tracing, core cursor register/thread state, bounded guest memory reads, memory watchpoint replay, and PEB-backed command-line extraction when `ttd_replay_bridge.dll` and TTD runtime DLLs are available.

## Build And Check Commands

Run these from the repository root:

```powershell
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p ttd-mcp
```

The runnable debug server is:

```text
target/debug/ttd-mcp.exe
```

For dependency setup and environment checks:

```powershell
cargo xtask doctor
cargo xtask deps
cargo xtask native-build
```

`cargo xtask deps` restores native NuGet packages into `target/nuget`, stages `dbghelp.dll`, `symsrv.dll`, and `srcsrv.dll` into `target/symbol-runtime`, and downloads `TTDReplay.dll` plus `TTDReplayCPU.dll` into `target/ttd-runtime`.

## Native Dependencies

Native package restore is driven by `native/ttd-replay-bridge/packages.config`.

Important packages:

- `Microsoft.TimeTravelDebugging.Apis` for TTD Replay headers and import libraries.
- `Microsoft.Debugging.Platform.SymSrv` for Microsoft symbol-server compatible symbol acquisition.
- `Microsoft.Debugging.Platform.SrcSrv` for source-server support next to symbol acquisition.
- `Microsoft.Debugging.Platform.DbgEng` for debugger-platform support if needed later.

Runtime replay DLLs come from the WinDbg/TTD distribution, not from the TTD API NuGet package.

## Symbols

The default symbol path is built in `crates/ttd-mcp/src/ttd_replay/symbols.rs` and should include:

```text
srv*.ttd-symbol-cache*https://msdl.microsoft.com/download/symbols
```

`cargo xtask deps` stages `dbghelp.dll`, `symsrv.dll`, and `srcsrv.dll` into `target/symbol-runtime`. Preserve support for caller-provided binary paths, symbol paths, and symbol cache directories. Public Microsoft symbols are enough for module and function names in many Windows binaries; private symbols are not expected for normal tests.

## Good Test Trace Target

The repository keeps a small reusable sample trace as `traces/ping.7z`. Keep the archive trackable, but keep extracted trace contents under `traces/ping/` local-only and ignored. The ping integration test extracts `traces/ping.7z` automatically with `7z` or `7zz`; use `TTD_TEST_7Z` if the extractor is not on `PATH`.

For a simple local TTD capture, prefer an in-box Windows executable with public symbols on the Microsoft symbol server. A good first target is:

```text
C:\Windows\System32\ping.exe 127.0.0.1 -n 3
```

This is easy to obtain, short-lived, deterministic enough for smoke tests, and its public PDBs should be available through `https://msdl.microsoft.com/download/symbols` on supported Windows builds.

If you want an interactive target that stays alive until closed, use:

```text
C:\Windows\System32\notepad.exe
```

Close the program cleanly so TTD finalizes the `.run` and `.idx` files.

## Safety And Repository Hygiene

- Treat `.run`, `.idx`, `.ttd`, `.pdb`, `.dll`, `.exe`, and other generated debugger artifacts as local-only unless the user explicitly asks otherwise.
- Keep reusable test traces compressed as `.7z` archives; do not commit their extracted directories.
- Do not commit downloaded Microsoft runtime binaries or captured traces.
- Keep edits focused. Do not refactor unrelated Rust modules while wiring native replay.
- Read current file contents before editing; this repo may have user or formatter edits between turns.
- Preserve placeholder errors until a real backend is wired, so unsupported tools fail clearly rather than returning misleading data.

## Likely Next Implementation Steps

1. Add full architecture-specific register contexts beyond the compact PC/SP/FP/TEB snapshot.
2. Add process artifact helpers beyond command-line extraction, such as basic stack inspection.
3. Expand module output with symbol loading details once symbolication is wired beyond raw module paths.
4. Add optional watchpoint replay limits or thread filters if large traces need narrower searches.
5. Expand black-box MCP stdio tests alongside new replay-backed tool behavior.