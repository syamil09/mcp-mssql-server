# mcp-mssql

> A read-only MCP (Model Context Protocol) server that connects AI agents like Claude Code to Microsoft SQL Server databases. Single Go binary, zero dependencies, defense-in-depth security.

## Architecture

```
Claude AI (cloud) <-- HTTPS --> Claude Code (local) <-- stdio --> mcp-mssql (local) <-- TCP 1433 --> SQL Server
```

SQL Server is never exposed to the internet. All database traffic stays local.

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

## MCP Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `query_database` | Execute a SELECT query. Auto-limited, validated, column-masked. | `sql` (string, required) |
| `list_tables` | List all queryable tables from `INFORMATION_SCHEMA.TABLES`. Blocked tables excluded. | none |
| `describe_table` | Get column names, data types, nullability for a table. Uses parameterized query. | `table_name` (string, required) |

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

Defines which tables to block, which columns to mask, and the max row limit.

```json
{
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
  "max_rows": 200
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

Verify the connection:

```
> What tools do you have available?
> List all tables in the database
> Describe the orders table
> Show me the top 5 rows from orders
```

## Config Lookup Priority

1. `MSSQL_CONFIG_FILE` env var -- explicit path override
2. `.mcp-mssql-config.json` -- auto-detected in working directory
3. `MSSQL_BLOCKED_TABLES` env var -- CSV fallback (e.g., `users,audit_log`)
4. Built-in defaults -- masks `password`, `password_hash`, `ssn`, `credit_card`, `salary`, `token`, `secret`, `api_key`

## Project Structure

```
mcp-mssql-server/
├── main.go          -- entry point, starts stdio MCP server
├── config.go        -- loads .mcp-mssql-config.json, env var fallback
├── db.go            -- connection pool, query execution, parameterized queries
├── security.go      -- query validation, table blocklist, column masking, audit log
├── tools.go         -- 3 MCP tools: query_database, list_tables, describe_table
├── go.mod           -- module: mcp-mssql (mcp-go v0.45.0, go-mssqldb v1.9.8)
└── go.sum
```

## Security Model

Six layers of defense, applied in order for every query:

| Layer | What It Prevents |
|-------|-----------------|
| 1. SELECT-only prefix check | Any non-SELECT/WITH statement |
| 2. Dangerous keyword regex | SQL injection keywords as whole words (no false positives on column values) |
| 3. Table blocklist | Querying tables listed in `blocked_tables` |
| 4. Column masking | Returning values from `sensitive_columns` even if explicitly requested |
| 5. Row limit cap | Context overflow from unbounded queries |
| 6. Audit + access logging | Undetected access to new sensitive tables |

## Audit Log Format

```
[CONFIG]   blocked_tables=6 sensitive_columns=8 max_rows=200
[ACCESS]   table=orders
[AUDIT]    time=2026-03-25T14:22:00Z status=SUCCESS rows=5 query="SELECT TOP 5 ..." error=""
[ACCESS]   table=users
[AUDIT]    time=2026-03-25T14:23:00Z status=BLOCKED rows=0 query="SELECT * FROM users" error="access to table 'users' is not permitted"
[SECURITY] masked sensitive column: salary
```

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

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/mark3labs/mcp-go` | v0.45.0 | MCP protocol implementation (JSON-RPC 2.0, stdio transport, tool registration) |
| `github.com/microsoft/go-mssqldb` | v1.9.8 | Official Microsoft SQL Server driver for Go |

## License

Internal / Confidential
