# SSIS ETL Tools for mcp-mssql

## Goal
Add 5 MCP tools to the existing Go mcp-mssql server that parse `.dtsx` SSIS packages on-demand to extract control flow, data flow, column mappings, table references, and impact analysis.

## Context
The mcp-mssql server (`mcp-mssql-server/` Go project) already handles SQL Server querying. New SSIS tools are purely additive — no DB connection needed, pure file I/O parsing `.dtsx` XML files from a configurable local path. No SQLite index — on-demand parsing for simplicity and freshness.

## Impact Map

| Layer | File | Change | Why |
|---|---|---|---|
| Config | `config.go` | Modify | Add `ProjectSSISPath` field + `SSISProjectPath` var |
| Tools registry | `tools.go` | Modify | Call `registerSSISTools(s)` |
| SSIS parser + handlers | `ssis.go` | **New** | All XML structs, helpers, and tool handlers |
| Config example | `.mcp-mssql-config.json.example` | Modify | Document `project_ssis_path` key |
| Binary | `mcp-mssql.exe` | Rebuild + copy | Deploy to `sam_be_api/` |

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| `project_ssis_path` not set | Low | Return clear error, don't crash server |
| Malformed `.dtsx` XML | Medium | Skip bad files silently in impact_check |
| Variable-based SQL not scanned | Medium | Known limitation — iteration 02 if needed |
| Existing DB tools unaffected | ✅ None | Purely additive |

## Iterations

| # | File | Description | Status |
|---|------|-------------|--------|
| 1 | [01-core-parser-and-tools.md](01-core-parser-and-tools.md) | Config extension, ssis.go parser, 5 MCP tools, build+deploy | planned |
