# mcp-mssql

> A read-only MCP (Model Context Protocol) server that connects AI agents like Claude Code to Microsoft SQL Server databases — including SSIS ETL package analysis. Single Go binary, zero dependencies, defense-in-depth security.

## Architecture

```
Claude AI (cloud) <-- HTTPS --> Claude Code (local) <-- stdio --> mcp-mssql (local) <-- TCP 1433 --> SQL Server
                                                                       |
                                                                       +-- File I/O --> .dtsx packages (SSIS)
```

SQL Server is never exposed to the internet. All database traffic stays local. SSIS tools parse `.dtsx` files directly from a configured path.

## Features

- **Read-only enforcement** -- only `SELECT` and `WITH` (CTE) queries allowed
- **Dangerous keyword blocking** -- `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `TRUNCATE`, `EXEC`, `EXECUTE`, `XP_CMDSHELL`, `OPENROWSET`, `BULK INSERT`, `MERGE`, and semicolons are blocked using word-boundary regex matching
- **Table blocklist** -- explicitly block sensitive tables via config; blocked tables are hidden from `list_tables` and `describe_table`
- **Column masking** -- sensitive columns (e.g., `password`, `salary`, `credit_card`) are automatically stripped from query results
- **Auto row limiting** -- `TOP N` injected into queries missing a row limit (default: 100, configurable)
- **Audit logging** -- every query logged with `[AUDIT]` tag (status, row count, query text); every table access logged with `[ACCESS]` tag
- **Per-project config** -- one binary, different `.mcp-mssql-config.json` per project
- **Parameterized queries** -- `describe_table` uses `@p1` parameters to prevent SQL injection
- **Single binary** -- no runtime dependencies; share the `.exe` with your team, no Go installation required
- **Stored procedure execution** -- safely execute read-only SPs with definition inspection
- **Query benchmarking** -- compare execution time and row counts between queries
- **SSIS package analysis** -- parse `.dtsx` files for control flow, data flow, table references, and column mappings
- **SSISDB catalog integration** -- list deployed packages and execution history from the server
- **TOON output format** -- optional token-optimized output that reduces token usage by 30-60%

## MCP Tools

### Database Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `query_database` | Execute a SELECT query. Auto-limited, validated, column-masked. | `sql` (required) |
| `list_tables` | List all queryable tables. Blocked tables excluded. | none |
| `describe_table` | Get column names, data types, nullability. Parameterized. | `table_name` (required) |
| `exec_sp` | Execute a read-only stored procedure. SP definition inspected first. | `procedure` (required), `params` |
| `benchmark_query` | Compare query performance (time + row count, no data returned). | `query1` (required), `query2` |

### SSIS Tools (File-based)

Parse `.dtsx` files from the configured `project_ssis_path`.

| Tool | Description | Parameters |
|------|-------------|------------|
| `ssis_list_packages` | List all `.dtsx` packages in the configured path. | none |
| `ssis_control_flow` | Extract task sequence, types, and embedded SQL from a package. | `package_name` (required) |
| `ssis_data_flow` | Extract data flow components, table names, SQL queries, column mappings. | `package_name` (required) |
| `ssis_impact_check` | Scan ALL packages for references to a table or column. Use before schema changes. | `table_name` (required), `column_name` |
| `ssis_table_refs` | List all tables a single package reads from or writes to. | `package_name` (required) |
| `ssis_schema_validate` | Cross-reference a package against the live DB schema. Reports missing tables/columns. | `package_name` (required) |

### SSIS Tools (Database-backed)

Query the `SSISDB` catalog for deployed packages and execution history.

| Tool | Description | Parameters |
|------|-------------|------------|
| `ssis_list_deployed` | List packages deployed to the SSISDB catalog on the server. | `folder_name`, `project_name` |
| `ssis_execution_history` | Get execution history with status, duration, and who ran it. | `package_name`, `status`, `limit` |

## Prerequisites

- **Go 1.21+** -- only needed to build the binary (not needed to run it)
- **Claude Code CLI** -- `npm install -g @anthropic-ai/claude-code`
- **SQL Server access** -- existing credentials with read access (TCP port 1433)

## Build

```bash
cd mcp-mssql-server
go build -o mcp-mssql.exe .
```

Cross-compile for other platforms:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o mcp-mssql .

# macOS
GOOS=darwin GOARCH=amd64 go build -o mcp-mssql-mac .
```

## Setup

Two files are needed in your project root:

### .mcp-mssql-config.json

Defines connection credentials, security rules, output format, and SSIS path.

```json
{
  "server": "16.0.0.8",
  "port": 1433,
  "database": "MyDatabase",
  "user": "my_user",
  "password": "my_password",
  "encrypt": false,
  "connection_timeout": 240,
  "blocked_tables": [
    "users",
    "user_sessions",
    "audit_log",
    "api_keys",
    "password_resets",
    "system_config"
  ],
  "sensitive_columns": [
    "password",
    "password_hash",
    "salary",
    "token",
    "secret",
    "credit_card",
    "pin",
    "api_key"
  ],
  "max_rows": 200,
  "output_format": "toon",
  "project_ssis_path": "C:\\path\\to\\SSIS\\project"
}
```

### .mcp.json

Claude Code config pointing to the binary and your SQL Server connection string.

**Using the compiled binary (recommended for teams):**

```json
{
  "mcpServers": {
    "mssql": {
      "command": "C:/path/to/mcp-mssql.exe",
      "env": {
        "MSSQL_CONNECTION_STRING": "sqlserver://user:password@host:1433?database=mydb&encrypt=disable"
      }
    }
  }
}
```

**Using `go run` (for development):**

```json
{
  "mcpServers": {
    "mssql": {
      "command": "go",
      "args": ["run", "."],
      "cwd": "C:/path/to/mcp-mssql-server",
      "env": {
        "MSSQL_CONNECTION_STRING": "sqlserver://user:password@host:1433?database=mydb&encrypt=disable"
      }
    }
  }
}
```

## Connection String Format

`go-mssqldb` uses URL format, not ADO.NET format:

```
sqlserver://username:password@host:1433?database=dbname&encrypt=disable&connection+timeout=240
```

Special characters in the password must be URL-encoded (e.g., `%` becomes `%25`).

## Usage

1. Place `.mcp.json` and `.mcp-mssql-config.json` in your project root
2. Run `claude` from that directory
3. Claude Code automatically starts the MCP server
4. Ask questions in natural language -- Claude uses the tools as needed

Example queries:

```
> List all tables in the database
> Describe the orders table
> Show me the top 5 rows from orders
> Execute stored procedure SAM_API_GetData with @id = '123'
> Compare performance of these two queries
```

SSIS examples:

```
> List all SSIS packages
> Show the control flow of BosNet Daily
> What tables does the SAM Report package use?
> Check if any SSIS package references the customers table
> Show execution history of failed SSIS packages
> List deployed packages in the SAM FIRESTORE folder
```

## Config Lookup Priority

1. `MSSQL_CONFIG_FILE` env var -- explicit path override
2. `.mcp-mssql-config.json` -- auto-detected in working directory
3. `MSSQL_BLOCKED_TABLES` env var -- CSV fallback (e.g., `users,audit_log`)
4. Built-in defaults -- masks `password`, `password_hash`, `ssn`, `credit_card`, `salary`, `token`, `secret`, `api_key`

### Config Fields

| Field | Type | Description |
|-------|------|-------------|
| `server` | string | SQL Server hostname or IP |
| `port` | int | SQL Server port (default: 1433) |
| `database` | string | Database name |
| `user` | string | SQL Server username |
| `password` | string | SQL Server password |
| `encrypt` | bool | Enable TLS encryption (default: false) |
| `connection_timeout` | int | Connection timeout in seconds |
| `blocked_tables` | string[] | Tables to hide and block from queries |
| `sensitive_columns` | string[] | Columns to mask in query results |
| `max_rows` | int | Maximum rows returned per query (default: 100) |
| `output_format` | string | `"json"` (default) or `"toon"` (token-optimized, 30-60% fewer tokens) |
| `project_ssis_path` | string | Path to local SSIS project directory containing `.dtsx` files |

## Project Structure

```
mcp-mssql-server/
├── main.go          -- entry point, starts stdio MCP server
├── config.go        -- loads .mcp-mssql-config.json, env var fallback, connection string builder
├── db.go            -- connection pool, query execution, parameterized queries
├── security.go      -- query validation, table blocklist, column masking, audit log
├── tools.go         -- database tools: query_database, list_tables, describe_table, exec_sp, benchmark_query
├── ssis.go          -- SSIS tools: package listing, control/data flow parsing, impact check, SSISDB queries
├── toon.go          -- TOON output format: token-optimized serialization for flat and nested data
├── go.mod           -- module: mcp-mssql (mcp-go v0.45.0, go-mssqldb v1.9.8)
└── go.sum
```

## Security Model

Seven layers of defense, applied in order for every query:

| Layer | What It Prevents |
|-------|-----------------|
| 1. SELECT-only prefix check | Any non-SELECT/WITH/DECLARE statement |
| 2. Dangerous keyword regex | SQL injection keywords as whole words (no false positives on column values) |
| 3. Table blocklist | Querying tables listed in `blocked_tables` |
| 4. SP definition inspection | `exec_sp` reads the SP source and blocks any containing write operations |
| 5. Column masking | Returning values from `sensitive_columns` even if explicitly requested |
| 6. Row limit cap | Context overflow from unbounded queries |
| 7. Audit + access logging | Undetected access to new sensitive tables |

## Audit Log Format

```
[CONFIG]   blocked_tables=6 sensitive_columns=8 max_rows=200
[ACCESS]   table=orders
[AUDIT]    time=2026-03-25T14:22:00Z status=SUCCESS rows=5 query="SELECT TOP 5 ..." error=""
[ACCESS]   table=users
[AUDIT]    time=2026-03-25T14:23:00Z status=BLOCKED rows=0 query="SELECT * FROM users" error="access to table 'users' is not permitted"
[SECURITY] masked sensitive column: salary
```

## Output Formats

### JSON (default)

Standard indented JSON. Best for nested data and human readability.

### TOON (Token-Oriented Object Notation)

Set `"output_format": "toon"` in config. Reduces token usage by 30-60% for tabular data. Uses compact tabular encoding for uniform arrays of objects.

```
count: 3
columns[2]: name,age
rows[3]{name,age}:
  Alice,30
  Bob,25
  Charlie,35
```

**Format rules by tool:**
- Database tools and flat SSIS tools (list, impact check, table refs) -- follow config setting
- `ssis_control_flow` and `ssis_data_flow` -- always JSON (nested structures don't suit tabular format)

## Troubleshooting

| Symptom | Resolution |
|---------|-----------|
| MCP server not found | Use absolute path in `.mcp.json` `command` field |
| `cannot reach SQL Server` | Check network/VPN. Test: `telnet host 1433` |
| Config file not loaded | Ensure `.mcp-mssql-config.json` is in the directory where you run `claude` |
| Tools not visible | Run `/mcp` in Claude Code to check MCP server status |
| Query blocked unexpectedly | Check audit log for `BLOCKED`. Query may contain a dangerous keyword |
| Results missing columns | Column is in `sensitive_columns` in config |
| `go run`: no go files listed | Use `go run .` (with the dot), not `go run` |
| SSIS tools return empty | Check `project_ssis_path` in config points to a directory with `.dtsx` files |
| SSISDB tools fail | Ensure SSISDB exists on the server and the connected user has read access to `SSISDB.catalog.*` views |
| `exec_sp` blocked | SP definition contains write operations (INSERT/UPDATE/DELETE). Only read-only SPs are allowed |

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/mark3labs/mcp-go` | v0.45.0 | MCP protocol implementation (JSON-RPC 2.0, stdio transport, tool registration) |
| `github.com/microsoft/go-mssqldb` | v1.9.8 | Official Microsoft SQL Server driver for Go |

## License

Internal / Confidential
