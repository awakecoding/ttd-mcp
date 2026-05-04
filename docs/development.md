# Development and advanced setup

This page keeps the deeper setup and contributor-oriented material out of the main README while preserving the details needed to build and work on the project.

## Workspace structure

| Path | Purpose |
| --- | --- |
| `Cargo.toml` | Workspace root |
| `crates\windbg-tool` | Main CLI binary crate |
| `crates\windbg-ttd` | MCP server, daemon, replay facade, and tool definitions |
| `crates\windbg-dbgeng` | DbgEng process-server and live-launch helpers |
| `crates\windbg-install` | WinDbg package install/update/launch support |
| `xtask` | Developer workflow commands |
| `native\ttd-replay-bridge` | C++ bridge to the TTD Replay API |
| `scripts\Get-TtdReplayRuntime.ps1` | Runtime acquisition helper |
| `docs\architecture.md` | Architecture notes and layering details |

## Build and check commands

Run these from the repository root:

```powershell
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build -p windbg-tool
```

## Dependency and native setup

Use a Visual Studio Developer PowerShell, or another environment where `nuget`, `cmake`, `msbuild`, and `powershell` are available:

```powershell
cargo xtask doctor
cargo xtask deps
cargo xtask native-build
```

`cargo xtask deps`:

- restores native NuGet packages into `target\nuget`
- stages `dbghelp.dll`, `symsrv.dll`, and `srcsrv.dll` into `target\symbol-runtime`
- stages DbgEng runtime DLLs into `target\dbgeng-runtime`
- downloads `TTDReplay.dll` and `TTDReplayCPU.dll` into `target\ttd-runtime`

`cargo xtask native-build` configures and builds the C++ bridge under `target\native\ttd-replay-bridge`.

To smoke-test the packaged MCP server:

```powershell
cargo xtask mcp-smoke
```

## Native dependencies

Native package restore is driven by `native\ttd-replay-bridge\packages.config`.

Important packages:

- `Microsoft.TimeTravelDebugging.Apis`
- `Microsoft.Debugging.Platform.SymSrv`
- `Microsoft.Debugging.Platform.SrcSrv`
- `Microsoft.Debugging.Platform.DbgEng`

Runtime replay still depends on `TTDReplay.dll` and `TTDReplayCPU.dll` from the WinDbg/TTD distribution.

## Symbols

The default symbol path is equivalent to:

```text
srv*.ttd-symbol-cache*https://msdl.microsoft.com/download/symbols
```

The project keeps symbol/runtime setup repo-local and process-local. It does not need to write debugger registry keys or machine-wide `_NT_SYMBOL_PATH` values as part of normal operation.

## Sample trace fixture

The repository keeps a reusable sample trace archive at `traces\ping.7z`. Extracted contents under `traces\ping\` are local-only and ignored by git.

After extraction, the fixture layout is:

```text
traces\ping\ping01.run
traces\ping\ping01.idx
traces\ping\ping.exe
```

If `7z` or `7zz` is not on `PATH`, set `TTD_TEST_7Z` to the extractor path.

## Local replay tests

Strict local replay checks:

```powershell
$env:TTD_RUNTIME_DIR = "D:\dev\windbg-tool\target\ttd-runtime"
$env:TTD_MCP_EXPECT_NATIVE_REPLAY = "1"
cargo test -p windbg-ttd --test ping_trace
cargo test -p windbg-tool --test daemon_cli
```

To force a custom trace instead of the committed archive fixture, set `TTD_TEST_TRACE` to a `.run` file path.

## Hygiene and safety

- Treat `.run`, `.idx`, `.ttd`, `.pdb`, `.dll`, and `.exe` artifacts as local-only unless explicitly requested otherwise
- Do not commit extracted traces or downloaded Microsoft runtime binaries
- Keep reusable trace fixtures compressed as `.7z`

## Related docs

- [README.md](../README.md)
- [architecture.md](architecture.md)
- [cli.md](cli.md)
- [mcp.md](mcp.md)
