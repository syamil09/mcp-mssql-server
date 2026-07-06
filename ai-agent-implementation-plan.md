# AI Agent Implementation Plan
## mcp-mssql — Generic SQL Server MCP Server

**Version:** 2.1 | **Date:** March 2026 | **Classification:** Internal / Confidential

> **What changed in v2.0:**
> - Renamed from `sam-mcp-server` → `mcp-mssql` (generic, reusable across all MSSQL projects)
> - Switched from table **whitelist** → table **blocklist** (more practical for large schemas)
> - Added `config.go` with `.mcp-mssql-config.json` as the per-project config file
> - `max_rows` is now configurable per project
> - `list_tables` now queries real `INFORMATION_SCHEMA` instead of returning a static list
>
> **What changed in v2.1 (security hardening):**
> - Fixed SQL injection in `describe_table` — switched from `fmt.Sprintf` to parameterized query (`@p1`)
> - Fixed `addRowLimitIfMissing` — now only prepends `TOP N` at query start, won't break subqueries
> - Fixed keyword blocking false positives — now uses word-boundary matching instead of `strings.Contains`
> - Added Windows path notes — binary is `mcp-mssql.exe`, paths use backslashes in `.mcp.json`
> - Pinned `mcp-go` dependency to verified version with correct API signatures

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Project Structure](#3-project-structure)
4. [Implementation Guide](#4-implementation-guide)
5. [MCP Tools Reference](#5-mcp-tools-reference)
6. [Security Reference](#6-security-reference)
7. [Implementation Phases](#7-implementation-phases)
8. [Troubleshooting](#8-troubleshooting)
9. [Quick Reference](#9-quick-reference)
10. [References](#10-references)

---

## 1. Overview

This document provides a complete technical implementation plan for integrating an AI agent (Claude Code via MCP) with any Microsoft SQL Server database. `mcp-mssql` is a generic, reusable MCP server — one binary, configured per project via `.mcp-mssql-config.json`.

### 1.1 Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                      Anthropic Cloud                            │
│                      Claude AI Model                            │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS (only conversation text crosses)
┌──────────────────────────▼──────────────────────────────────────┐
│                    Your Local Machine                           │
│                                                                 │
│  ┌──────────────────┐    stdio pipe     ┌───────────────────┐  │
│  │  Claude Code CLI │ ◄───────────────► │    mcp-mssql      │  │
│  │  (terminal)      │   JSON-RPC 2.0    │  (Go binary)      │  │
│  └──────────────────┘                   │  • SELECT only    │  │
│                                         │  • table blocklist│  │
│                                         │  • column masking │  │
│                                         │  • audit logging  │  │
│                                         └────────┬──────────┘  │
│                                                  │ reads       │
│                                    ┌─────────────▼──────────┐  │
│                                    │ .mcp-mssql-config.json │  │
│                                    └─────────────┬──────────┘  │
│                                                  │ TCP 1433    │
│                                         ┌────────▼──────────┐  │
│                                         │    SQL Server     │  │
│                                         │ (existing creds)  │  │
│                                         └───────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Description |
|---|---|
| Claude Code CLI | Terminal tool that bridges Claude AI (cloud) with local MCP server via stdio pipe |
| mcp-mssql | Generic Go binary — validates queries, masks columns, logs all activity |
| .mcp-mssql-config.json | Per-project config — blocked tables, sensitive columns, max rows |
| SQL Server | Any MSSQL database — accessed via existing credentials, no new DB users required |

### 1.2 Key Design Decisions

- **Generic** — one binary works for any MSSQL project, config differs per project via `.mcp-mssql-config.json`
- **Blocklist approach** — all tables readable by default, explicitly block sensitive ones
- **No new SQL Server user required** — uses existing credentials
- **Read-only by design** — security enforced at application layer, not DB layer
- **Claude Max subscription compatible** — no API key required for MCP server itself
- **stdio transport** — MCP server runs locally, zero internet exposure for database
- **Defense in depth** — validation + column masking + row limits + audit logging

### 1.3 Whitelist vs Blocklist

`mcp-mssql` uses a **blocklist** approach — all tables are readable unless explicitly blocked.

| | Whitelist | Blocklist (mcp-mssql) |
|---|---|---|
| **Default stance** | Deny all, allow explicitly | Allow all, deny explicitly |
| **New table added to DB** | Blocked automatically ✓ | Accessible automatically ⚠️ |
| **Maintenance burden** | List every safe table | List only sensitive tables |
| **Best for** | Small, controlled schema | Large schema, mostly safe |
| **Risk if you forget** | Feature broken | Table exposed |

> **Mitigation for blocklist risk:** `mcp-mssql` logs every table accessed (`[ACCESS]` log entries). Review access logs periodically and add newly sensitive tables to `blocked_tables` in `.mcp-mssql-config.json`.

### 1.4 Security Model

> **Security Principle: Defense in Depth**
>
> The MCP server enforces security at the application layer. Even if Claude AI generates a harmful query, the server blocks it before it reaches SQL Server. Four independent controls work in concert:
> 1. Query validation (SELECT-only, no dangerous keywords)
> 2. Table blocklist (explicitly blocked tables rejected)
> 3. Column masking (sensitive columns stripped from results)
> 4. Row limit cap (prevents context window overflow)

---

## 2. Prerequisites

### 2.1 Required Tools

| Tool | Purpose / Install |
|---|---|
| Go 1.21+ | Build the MCP server binary — golang.org/dl |
| Claude Code CLI | AI agent interface — `npm install -g @anthropic-ai/claude-code` |
| Claude Max Subscription | Authentication for Claude Code (no API key needed for MCP server) |
| Git | Version control for mcp-mssql source code |
| SQL Server access | Existing connection credentials (read access sufficient) |

### 2.2 Go Dependencies

| Package | Purpose |
|---|---|
| `github.com/mark3labs/mcp-go` | MCP protocol implementation — handles JSON-RPC 2.0, stdio transport, tool registration |
| `github.com/microsoft/go-mssqldb` | Official Microsoft SQL Server driver for Go |

### 2.3 Network Requirements

- SQL Server must be reachable from the local machine (TCP port 1433)
- Claude Code requires internet access to reach `api.anthropic.com` (HTTPS port 443)
- No inbound ports required — MCP server uses outbound connections only
- VPN access may be required if SQL Server is on internal network

> **Important: SQL Server is NEVER exposed to the internet.**
>
> The MCP server runs entirely on your local machine. Only the conversation text (your questions and Claude's answers) crosses the internet to Anthropic's API. Database query results travel locally: SQL Server → mcp-mssql → Claude Code → Claude API.

---

## 3. Project Structure

```
mcp-mssql/                         ← source code repo (one, shared)
├── main.go
├── config.go
├── db.go
├── security.go
├── tools.go
└── go.mod

your-project/                      ← per-project files (committed to each repo)
├── .mcp.json                      ← Claude Code config
├── .mcp-mssql-config.json         ← blocked tables, sensitive columns, max rows
└── ...
```

### 3.1 File Responsibilities

| File | Responsibility |
|---|---|
| `main.go` | Reads env vars, calls `LoadConfig()`, initializes DB, creates MCP server, starts stdio listener |
| `config.go` | Loads `.mcp-mssql-config.json` → builds `BlockedTables`, `SensitiveColumns`, `MaxRows` |
| `db.go` | Connection pool management, query execution, result serialization to `QueryResult` struct |
| `security.go` | SELECT-only validation, blocklist check, column masking, audit log writer |
| `tools.go` | Three MCP tools: `query_database`, `list_tables`, `describe_table` |

### 3.2 Config Lookup Priority

```
1. MSSQL_CONFIG_FILE env var        → explicit override path (any location)
2. .mcp-mssql-config.json           → auto-detected in current working directory
3. MSSQL_BLOCKED_TABLES env var     → CSV fallback for simple cases
4. Built-in sensitive column defaults → last resort if nothing configured
```

### 3.3 Data Flow Within the Server

Every tool call follows this exact execution order — no exceptions:

1. Claude Code receives tool call via stdin (JSON-RPC 2.0 format)
2. `tools.go` extracts SQL query parameter from request
3. `security.go ValidateQuery()` checks: SELECT-only, no dangerous keywords, not in blocklist
4. If validation fails → return error response, write `BLOCKED` to audit log, **stop here**
5. `db.go ExecuteQuery()` executes the validated query against SQL Server
6. `security.go MaskSensitiveColumns()` strips sensitive columns from results
7. `security.go AuditLog()` writes `SUCCESS` entry with query and row count
8. `tools.go` serializes result to JSON, returns via MCP response
9. Claude Code sends result back to Claude AI as `tool_result`
10. Claude AI reads JSON, composes natural language answer

---

## 4. Implementation Guide

### 4.1 Initialize Project

```bash
mkdir mcp-mssql && cd mcp-mssql
go mod init mcp-mssql
go get github.com/mark3labs/mcp-go@latest
go get github.com/microsoft/go-mssqldb@latest
```

### 4.2 config.go — Configuration Loader

```go
package main

import (
    "encoding/json"
    "log"
    "os"
    "strings"
)

type Config struct {
    BlockedTables    []string `json:"blocked_tables"`
    SensitiveColumns []string `json:"sensitive_columns"`
    MaxRows          int      `json:"max_rows"`
}

var BlockedTables    map[string]bool
var SensitiveColumns map[string]bool
var MaxRows          int

func LoadConfig() {
    cfg := loadConfigFile()

    BlockedTables    = toMap(cfg.BlockedTables)
    SensitiveColumns = toMap(cfg.SensitiveColumns)
    MaxRows          = cfg.MaxRows
    if MaxRows == 0 {
        MaxRows = 100
    }

    // Built-in sensitive column defaults if nothing configured
    if len(SensitiveColumns) == 0 {
        SensitiveColumns = map[string]bool{
            "password": true, "password_hash": true,
            "salary":   true, "token":         true,
            "secret":   true, "api_key":        true,
        }
    }

    log.Printf("[CONFIG] blocked_tables=%d sensitive_columns=%d max_rows=%d",
        len(BlockedTables), len(SensitiveColumns), MaxRows)
}

func loadConfigFile() Config {
    var cfg Config

    // Priority 1: explicit path via env var
    configPath := os.Getenv("MSSQL_CONFIG_FILE")

    // Priority 2: default filename in current directory
    if configPath == "" {
        configPath = ".mcp-mssql-config.json"
    }

    data, err := os.ReadFile(configPath)
    if err != nil {
        // Config file is optional — fall back to env vars
        log.Printf("[CONFIG] no config file at %s, falling back to env vars", configPath)
        cfg.BlockedTables    = splitCSV(os.Getenv("MSSQL_BLOCKED_TABLES"))
        cfg.SensitiveColumns = splitCSV(os.Getenv("MSSQL_SENSITIVE_COLUMNS"))
        return cfg
    }

    if err := json.Unmarshal(data, &cfg); err != nil {
        log.Fatalf("[CONFIG] invalid JSON in %s: %v", configPath, err)
    }

    log.Printf("[CONFIG] loaded from %s", configPath)
    return cfg
}

func toMap(items []string) map[string]bool {
    result := make(map[string]bool)
    for _, item := range items {
        key := strings.ToLower(strings.TrimSpace(item))
        if key != "" {
            result[key] = true
        }
    }
    return result
}

func splitCSV(s string) []string {
    if s == "" {
        return nil
    }
    parts := strings.Split(s, ",")
    result := make([]string, 0, len(parts))
    for _, p := range parts {
        if t := strings.TrimSpace(p); t != "" {
            result = append(result, t)
        }
    }
    return result
}
```

### 4.3 db.go — Database Layer

```go
package main

import (
    "context"
    "database/sql"
    "fmt"
    "time"

    _ "github.com/microsoft/go-mssqldb"
)

type Database struct {
    pool *sql.DB
}

func NewDatabase(connString string) (*Database, error) {
    pool, err := sql.Open("sqlserver", connString)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }

    pool.SetMaxOpenConns(5)
    pool.SetMaxIdleConns(2)
    pool.SetConnMaxLifetime(30 * time.Minute)

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if err := pool.PingContext(ctx); err != nil {
        return nil, fmt.Errorf("cannot reach SQL Server: %w", err)
    }

    return &Database{pool: pool}, nil
}

type QueryResult struct {
    Columns []string                 `json:"columns"`
    Rows    []map[string]interface{} `json:"rows"`
    Count   int                      `json:"count"`
}

func (db *Database) ExecuteQuery(ctx context.Context, query string) (*QueryResult, error) {
    rows, err := db.pool.QueryContext(ctx, query)
    if err != nil {
        return nil, fmt.Errorf("query failed: %w", err)
    }
    defer rows.Close()

    columns, err := rows.Columns()
    if err != nil {
        return nil, fmt.Errorf("failed to get columns: %w", err)
    }

    var result QueryResult
    result.Columns = columns

    for rows.Next() {
        values := make([]interface{}, len(columns))
        valuePtrs := make([]interface{}, len(columns))
        for i := range values {
            valuePtrs[i] = &values[i]
        }
        if err := rows.Scan(valuePtrs...); err != nil {
            return nil, fmt.Errorf("failed to scan row: %w", err)
        }
        row := make(map[string]interface{})
        for i, col := range columns {
            row[col] = values[i]
        }
        result.Rows = append(result.Rows, row)
    }

    result.Count = len(result.Rows)
    return &result, nil
}

// ExecuteQueryParam executes a parameterized query (e.g., WHERE col = @p1).
// Use this instead of fmt.Sprintf for any query that includes user-supplied values
// to prevent SQL injection attacks.
func (db *Database) ExecuteQueryParam(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
    rows, err := db.pool.QueryContext(ctx, query, args...)
    if err != nil {
        return nil, fmt.Errorf("query failed: %w", err)
    }
    defer rows.Close()

    columns, err := rows.Columns()
    if err != nil {
        return nil, fmt.Errorf("failed to get columns: %w", err)
    }

    var result QueryResult
    result.Columns = columns

    for rows.Next() {
        values := make([]interface{}, len(columns))
        valuePtrs := make([]interface{}, len(columns))
        for i := range values {
            valuePtrs[i] = &values[i]
        }
        if err := rows.Scan(valuePtrs...); err != nil {
            return nil, fmt.Errorf("failed to scan row: %w", err)
        }
        row := make(map[string]interface{})
        for i, col := range columns {
            row[col] = values[i]
        }
        result.Rows = append(result.Rows, row)
    }

    result.Count = len(result.Rows)
    return &result, nil
}
```

### 4.4 security.go — Security Layer

```go
package main

import (
    "fmt"
    "log"
    "regexp"
    "strings"
    "time"
    "unicode"
)

// dangerousPattern matches dangerous SQL keywords as whole words only.
// This prevents false positives like "INSERT" matching inside column values
// or WHERE clauses (e.g., WHERE description LIKE '%INSERT%' is safe).
var dangerousPattern = regexp.MustCompile(
    `(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE|XP_CMDSHELL|SP_|OPENROWSET|BULK\s+INSERT|MERGE)\b|;`,
)

func ValidateQuery(sql string) error {
    normalized := strings.TrimSpace(sql)
    upper := strings.ToUpper(normalized)

    // Rule 1: Must start with SELECT or WITH
    if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
        return fmt.Errorf("only SELECT queries are allowed, got: %.20s...", normalized)
    }

    // Rule 2: Block dangerous keywords (whole-word match to avoid false positives)
    if match := dangerousPattern.FindString(normalized); match != "" {
        return fmt.Errorf("query contains forbidden keyword: %s", strings.ToUpper(match))
    }

    // Rule 3: Check against blocklist
    if len(BlockedTables) > 0 {
        if err := checkTableAccess(upper); err != nil {
            return err
        }
    }

    return nil
}

func checkTableAccess(upperQuery string) error {
    words := strings.FieldsFunc(upperQuery, func(r rune) bool {
        return unicode.IsSpace(r) || r == ',' || r == '(' || r == ')'
    })

    captureNext := false
    for _, word := range words {
        if word == "FROM" || word == "JOIN" {
            captureNext = true
            continue
        }
        if captureNext && word != "" {
            parts := strings.Split(word, ".")
            tableName := strings.ToLower(parts[len(parts)-1])
            tableName = strings.Trim(tableName, "[]\"'")

            // Log every table accessed — review periodically for new sensitive tables
            log.Printf("[ACCESS] table=%s", tableName)

            if BlockedTables[tableName] {
                return fmt.Errorf("access to table '%s' is not permitted", tableName)
            }
            captureNext = false
        }
    }
    return nil
}

func MaskSensitiveColumns(result *QueryResult) *QueryResult {
    maskedIndices := make(map[int]bool)
    safeColumns := []string{}

    for i, col := range result.Columns {
        if SensitiveColumns[strings.ToLower(col)] {
            maskedIndices[i] = true
            log.Printf("[SECURITY] masked sensitive column: %s", col)
        } else {
            safeColumns = append(safeColumns, col)
        }
    }

    if len(maskedIndices) == 0 {
        return result
    }

    safeRows := make([]map[string]interface{}, len(result.Rows))
    for i, row := range result.Rows {
        safeRow := make(map[string]interface{})
        for col, val := range row {
            if !SensitiveColumns[strings.ToLower(col)] {
                safeRow[col] = val
            }
        }
        safeRows[i] = safeRow
    }

    return &QueryResult{Columns: safeColumns, Rows: safeRows, Count: result.Count}
}

func AuditLog(query string, success bool, rowCount int, err error) {
    status, errMsg := "SUCCESS", ""
    if !success {
        status = "BLOCKED"
        errMsg = err.Error()
    }
    log.Printf("[AUDIT] time=%s status=%s rows=%d query=%q error=%q",
        time.Now().Format(time.RFC3339), status, rowCount, query, errMsg)
}
```

### 4.5 tools.go — MCP Tools

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "regexp"
    "strings"

    "github.com/mark3labs/mcp-go/mcp"
)

func registerTools(s *mcp.Server, db *Database) {
    s.AddTool(
        mcp.NewTool("query_database",
            mcp.WithDescription("Execute a SELECT query against the SQL Server database."),
            mcp.WithString("sql", mcp.Required(),
                mcp.Description("The SQL SELECT query to execute. Must start with SELECT or WITH.")),
        ),
        func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
            return handleQuery(ctx, req, db)
        },
    )

    s.AddTool(
        mcp.NewTool("list_tables",
            mcp.WithDescription("List all tables available for querying (excludes blocked tables)."),
        ),
        func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
            return handleListTables(ctx, db)
        },
    )

    s.AddTool(
        mcp.NewTool("describe_table",
            mcp.WithDescription("Get column names and data types for a specific table."),
            mcp.WithString("table_name", mcp.Required(),
                mcp.Description("Name of the table to describe.")),
        ),
        func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
            return handleDescribeTable(ctx, req, db)
        },
    )
}

func handleQuery(ctx context.Context, req mcp.CallToolRequest, db *Database) (*mcp.CallToolResult, error) {
    sqlQuery, ok := req.Params.Arguments["sql"].(string)
    if !ok || strings.TrimSpace(sqlQuery) == "" {
        return mcp.NewToolResultError("sql parameter is required"), nil
    }

    if err := ValidateQuery(sqlQuery); err != nil {
        AuditLog(sqlQuery, false, 0, err)
        return mcp.NewToolResultError(fmt.Sprintf("Query blocked: %s", err.Error())), nil
    }

    finalQuery := addRowLimitIfMissing(sqlQuery, MaxRows)

    result, err := db.ExecuteQuery(ctx, finalQuery)
    if err != nil {
        AuditLog(sqlQuery, false, 0, err)
        return mcp.NewToolResultError(fmt.Sprintf("Query failed: %s", err.Error())), nil
    }

    safeResult := MaskSensitiveColumns(result)
    AuditLog(sqlQuery, true, safeResult.Count, nil)

    jsonBytes, err := json.MarshalIndent(safeResult, "", "  ")
    if err != nil {
        return mcp.NewToolResultError("failed to serialize results"), nil
    }
    return mcp.NewToolResultText(string(jsonBytes)), nil
}

func handleListTables(ctx context.Context, db *Database) (*mcp.CallToolResult, error) {
    // Query real schema, then filter out blocked tables
    result, err := db.ExecuteQuery(ctx,
        "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME",
    )
    if err != nil {
        return mcp.NewToolResultError(fmt.Sprintf("failed to list tables: %s", err.Error())), nil
    }

    var available []string
    for _, row := range result.Rows {
        name := strings.ToLower(fmt.Sprintf("%v", row["TABLE_NAME"]))
        if !BlockedTables[name] {
            available = append(available, name)
        }
    }

    out := map[string]interface{}{
        "tables": available,
        "note":   "Blocked tables are excluded from this list.",
    }
    jsonBytes, _ := json.MarshalIndent(out, "", "  ")
    return mcp.NewToolResultText(string(jsonBytes)), nil
}

func handleDescribeTable(ctx context.Context, req mcp.CallToolRequest, db *Database) (*mcp.CallToolResult, error) {
    tableName, ok := req.Params.Arguments["table_name"].(string)
    if !ok {
        return mcp.NewToolResultError("table_name parameter is required"), nil
    }

    if BlockedTables[strings.ToLower(tableName)] {
        return mcp.NewToolResultError(fmt.Sprintf("table '%s' is not accessible", tableName)), nil
    }

    // Use parameterized query to prevent SQL injection.
    // NEVER use fmt.Sprintf to interpolate user input into SQL.
    descQuery := `
        SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME = @p1
        ORDER BY ORDINAL_POSITION
    `

    result, err := db.ExecuteQueryParam(ctx, descQuery, tableName)
    if err != nil {
        return mcp.NewToolResultError(fmt.Sprintf("failed to describe table: %s", err.Error())), nil
    }

    safeResult := MaskSensitiveColumns(result)
    jsonBytes, _ := json.MarshalIndent(safeResult, "", "  ")
    return mcp.NewToolResultText(string(jsonBytes)), nil
}

// addRowLimitIfMissing injects TOP N into the outermost SELECT only.
// It uses a regex anchored to the start of the query so subqueries like
// SELECT x FROM (SELECT ...) are not affected.
var selectAtStart = regexp.MustCompile(`(?i)^(\s*(?:WITH\s+.+?\)\s+)?SELECT)\s`)

func addRowLimitIfMissing(query string, limit int) string {
    upper := strings.ToUpper(strings.TrimSpace(query))
    if strings.Contains(upper, "TOP ") || strings.Contains(upper, "FETCH NEXT") {
        return query
    }
    loc := selectAtStart.FindStringIndex(query)
    if loc == nil {
        return query // shouldn't happen — ValidateQuery already checked prefix
    }
    insertPos := loc[1] - 1 // position right after "SELECT"
    return query[:insertPos] + fmt.Sprintf(" TOP %d", limit) + query[insertPos:]
}
```

### 4.6 main.go — Entry Point

```go
package main

import (
    "log"
    "os"

    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
)

func main() {
    // Load .mcp-mssql-config.json (or env var fallback)
    LoadConfig()

    connString := os.Getenv("MSSQL_CONNECTION_STRING")
    if connString == "" {
        log.Fatal("MSSQL_CONNECTION_STRING environment variable is required")
    }

    db, err := NewDatabase(connString)
    if err != nil {
        log.Fatalf("Failed to connect to database: %v", err)
    }
    log.Println("Connected to SQL Server successfully")

    s := mcp.NewServer("mcp-mssql", "2.0.0",
        mcp.WithServerInstructions(`
            You are connected to a SQL Server database via mcp-mssql.
            You can only READ data — no writes, updates, or deletions are possible.
            Always be conservative with row counts. Start with small limits before
            requesting large datasets. Some tables and columns may be restricted
            for security reasons — respect those boundaries.
        `),
    )

    registerTools(s, db)

    log.Println("mcp-mssql starting (stdio transport)...")
    if err := server.ServeStdio(s); err != nil {
        log.Fatalf("Server error: %v", err)
    }
}
```

### 4.7 Build & Deploy

```bash
# Build binary — Windows (produces mcp-mssql.exe)
go build -o mcp-mssql.exe .

# Build binary — Linux/macOS (if deploying to a server)
# GOOS=linux GOARCH=amd64 go build -o mcp-mssql .

# Move to stable shared location (Windows)
mkdir -p "$USERPROFILE/bin"
mv mcp-mssql.exe "$USERPROFILE/bin/"

# Move to stable shared location (macOS/Linux)
# mkdir -p ~/bin
# mv mcp-mssql ~/bin/
```

> **Windows note:** Go produces `mcp-mssql.exe` on Windows. Use the full `.exe` path in `.mcp.json`. Forward slashes work in JSON paths on Windows (e.g., `C:/Users/you/bin/mcp-mssql.exe`).

### 4.8 Per-Project Setup

Every project needs two files in its root directory:

**`.mcp-mssql-config.json`** — blocklist config for this project:

```json
{
  "blocked_tables": [
    "users",
    "user_sessions",
    "audit_log",
    "hr_salaries",
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
    "pin"
  ],
  "max_rows": 200
}
```

**`.mcp.json`** — Claude Code config pointing to the shared binary:

```json
{
  "mcpServers": {
    "mssql": {
      "command": "C:/Users/yourname/bin/mcp-mssql.exe",
      "env": {
        "MSSQL_CONNECTION_STRING": "Server=192.168.1.10;Database=YOUR_DB;User Id=user;Password=pass;Encrypt=false;"
      }
    }
  }
}
```

> **Note:** `MSSQL_CONFIG_FILE` env var is not needed — `mcp-mssql` automatically looks for `.mcp-mssql-config.json` in the directory where you run `claude`. Only set it if your config file is in a non-standard location.

> **Note:** Always use an absolute path in `command`. Relative paths fail silently. On Windows, use forward slashes in JSON (e.g., `C:/Users/...`) — both Go and Claude Code handle them correctly.

### 4.9 Adding mcp-mssql to a New Project

```bash
# 1. Copy config template
cp ~/templates/.mcp-mssql-config.json ~/projects/new-project/

# 2. Edit blocked tables for this specific project
nano ~/projects/new-project/.mcp-mssql-config.json

# 3. Create .mcp.json
cat > ~/projects/new-project/.mcp.json << 'EOF'
{
  "mcpServers": {
    "mssql": {
      "command": "/Users/yourname/bin/mcp-mssql",
      "env": {
        "MSSQL_CONNECTION_STRING": "Server=...;Database=NEW_DB;..."
      }
    }
  }
}
EOF

# 4. Start Claude Code from project root
cd ~/projects/new-project && claude
```

### 4.10 Verify Installation

```bash
# Login with Max subscription
claude login   # choose "Claude account with subscription"

# Start from project root (where .mcp.json and .mcp-mssql-config.json live)
cd ~/projects/your-project
claude

# Verify tools and config loaded
> What tools do you have available?
# Expected: query_database, list_tables, describe_table

/status
```

---

## 5. MCP Tools Reference

`mcp-mssql` exposes three tools to Claude. These are the **only operations** the AI agent can perform.

### 5.1 query_database

| Property | Value |
|---|---|
| Parameter | `sql` (string, required) |
| Allowed prefixes | `SELECT`, `WITH` (CTEs) |
| Forbidden keywords | `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `TRUNCATE`, `EXEC`, `XP_CMDSHELL`, semicolons |
| Auto row limit | Adds `TOP {max_rows}` if no `LIMIT`/`TOP` clause present |
| Column masking | Strips `sensitive_columns` automatically |

**Request:**
```json
{
  "jsonrpc": "2.0", "id": 7,
  "method": "tools/call",
  "params": {
    "name": "query_database",
    "arguments": { "sql": "SELECT TOP 5 order_id, customer_name, total_amount FROM orders ORDER BY created_at DESC" }
  }
}
```

**Success response:**
```json
{
  "jsonrpc": "2.0", "id": 7,
  "result": {
    "content": [{ "type": "text", "text": "{ \"columns\": [...], \"rows\": [...], \"count\": 5 }" }],
    "isError": false
  }
}
```

**Blocked response:**
```json
{
  "jsonrpc": "2.0", "id": 8,
  "result": {
    "content": [{ "type": "text", "text": "Query blocked: access to table 'users' is not permitted" }],
    "isError": true
  }
}
```

### 5.2 list_tables

Queries `INFORMATION_SCHEMA.TABLES` and filters out `blocked_tables`. Claude sees the real schema minus restricted tables.

### 5.3 describe_table

Returns column names and data types. Blocked tables and `sensitive_columns` are excluded from the schema.

---

## 6. Security Reference

### 6.1 Security Layers

| Layer | What It Prevents |
|---|---|
| 1. SELECT-only validation | `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `EXEC` — any write or DDL |
| 2. Dangerous keyword check | SQL injection via semicolons, `xp_cmdshell`, `OPENROWSET`, `BULK INSERT`, `MERGE` |
| 3. Table blocklist | Querying tables listed in `blocked_tables` in `.mcp-mssql-config.json` |
| 4. Column masking | Returning `sensitive_columns` even if query explicitly requests them |
| 5. Row limit cap | Pulling more than `max_rows` rows — prevents context overflow and bulk exposure |
| 6. Audit + access logging | `[AUDIT]` for every query result, `[ACCESS]` for every table touched |

### 6.2 Threat Model

| Threat | Vector | Mitigation | Status |
|---|---|---|---|
| Prompt injection via DB data | Malicious text in a DB record triggers harmful query | SELECT-only blocks all writes | ✓ Mitigated |
| Accidental DELETE/UPDATE | Claude misinterprets "clean up data" | Hard block on non-SELECT keywords | ✓ Mitigated |
| Sensitive data exposure | Query requests `password`/`salary` columns | Column masking in `security.go` | ✓ Mitigated |
| Blocked table access | Query targets `users` or `hr_salaries` | Blocklist check in `security.go` | ✓ Mitigated |
| New sensitive table exposure | New DB table not yet in blocklist | `[ACCESS]` log + periodic review | ⚠️ Process |
| Context window overflow | Query returns millions of rows | `max_rows` cap enforced | ✓ Mitigated |
| Training data exposure | DB results used to train Claude | Use API key (commercial terms) | Phase 2 |
| Shadow AI usage | Team uses personal Claude with real data | Team policy + training required | Process |

### 6.3 Data Privacy: Claude Max vs API Key

| Account Type | Training | Retention | Recommended For |
|---|---|---|---|
| Claude Max (consumer) | Opt-out required | 30 days if opted out | Development / internal use |
| Anthropic API key | Never — flat policy | 7 days auto-delete | Production with sensitive data |
| Enterprise + ZDR | Never | 0 days (immediate delete) | Highest sensitivity |

> **Action Required:** If using Claude Max, go to `claude.ai → Settings → Privacy → "Help improve Claude"` and set the toggle to **OFF**.

---

## 7. Implementation Phases

| Phase | Task | Description | Target |
|---|---|---|---|
| Phase 1 | Core mcp-mssql | Build binary with SELECT-only validation, blocklist, column masking, audit log, config loader | Week 1 |
| Phase 1 | Local Testing | Test all three tools, verify blocked tables and columns return proper errors | Week 1 |
| Phase 1 | First Project (SAM) | Add `.mcp.json` + `.mcp-mssql-config.json` to SAM project, test 10+ sample queries | Week 1 |
| Phase 2 | API Key Setup | Create Anthropic Console account, configure API key for production use | Week 2 |
| Phase 2 | Hybrid Auth | Alias/script to switch between Max (daily coding) and API key (sensitive data queries) | Week 2 |
| Phase 2 | Second Project | Add `.mcp-mssql-config.json` to BOSNET or other MSSQL project — same binary | Week 2 |
| Phase 3 | Audit Log Pipeline | Route `[AUDIT]` and `[ACCESS]` logs to Azure Monitor or ELK | Week 3–4 |
| Phase 3 | Review Process | Schedule monthly review of `[ACCESS]` logs for new sensitive tables | Week 3–4 |
| Phase 3 | Team Rollout | Document Shadow AI policy, add config files to team onboarding checklist | Week 3–4 |
| Phase 3 | AURA Integration | Connect mcp-mssql to AURA AI copilot for sales forecast and recommendation queries | Week 4+ |

---

## 8. Troubleshooting

| Symptom | Resolution |
|---|---|
| MCP server not found | Verify `.mcp.json` uses absolute path. Run: `ls ~/bin/mcp-mssql` |
| `cannot reach SQL Server` | Check connectivity: `telnet your-server 1433`. Check VPN. |
| Config file not loaded | Confirm `.mcp-mssql-config.json` exists in the directory where you run `claude`. Check startup log for `[CONFIG]` line. |
| Tools not visible | Run `/status`. Check terminal for MCP server startup errors. |
| Query blocked unexpectedly | Check audit log for `BLOCKED`. Query may contain semicolons or a dangerous keyword. |
| Table blocked unexpectedly | Table is in `blocked_tables` in `.mcp-mssql-config.json`. Remove it if safe. |
| Results missing columns | Column is in `sensitive_columns`. Check config and remove if safe to expose. |
| Claude Code using API key | Run: `echo $ANTHROPIC_API_KEY`. If set: `unset ANTHROPIC_API_KEY`, restart Claude Code. |
| Too many rows / context overflow | Increase `max_rows` in config, or ask Claude to use explicit `TOP N` in queries. |
| Invalid JSON in config | Run: `cat .mcp-mssql-config.json \| python3 -m json.tool` to validate. |

---

## 9. Quick Reference

### 9.1 Daily Workflow

1. Open terminal in your project root (where `.mcp.json` and `.mcp-mssql-config.json` live)
2. Run `claude` (Max) or `ANTHROPIC_API_KEY=sk-ant-... claude` (API key for production)
3. Claude Code starts `mcp-mssql` and loads `.mcp-mssql-config.json` automatically
4. Ask questions in natural language
5. Review `[ACCESS]` logs periodically for new sensitive tables

### 9.2 Key Files

| File | Location | Purpose |
|---|---|---|
| `mcp-mssql` binary | `~/bin/mcp-mssql` | Shared across all projects — rebuild here when code changes |
| `.mcp.json` | Each project root | Claude Code config — binary path + connection string |
| `.mcp-mssql-config.json` | Each project root | Blocklist config — per-project, committed to Git |
| `~/.claude/settings.json` | Home dir | Claude Code global settings |

### 9.3 Useful Commands

```bash
# Check auth status and active MCP servers
claude /status

# Rebuild binary after code changes
cd ~/projects/mcp-mssql && go build -o ~/bin/mcp-mssql . && claude

# Validate config JSON before starting
cat .mcp-mssql-config.json | python3 -m json.tool

# Start with API key (production / sensitive data)
ANTHROPIC_API_KEY=sk-ant-api03-... claude

# Alias for convenience — add to ~/.zshrc or ~/.bashrc
alias claude-prod='ANTHROPIC_API_KEY=sk-ant-api03-... claude'

# Check if API key is active (empty = using Max subscription)
echo $ANTHROPIC_API_KEY
```

### 9.4 MCP Protocol Cheat Sheet

| JSON-RPC Method | When It Happens |
|---|---|
| `initialize` | Once at startup — Claude Code introduces itself |
| `tools/list` | Once after initialize — Claude discovers available tools |
| `tools/call` | Every time Claude queries the database |
| `notifications/initialized` | Handshake completion |

### 9.5 Audit Log Format

```
[CONFIG]   loaded from .mcp-mssql-config.json
[CONFIG]   blocked_tables=7 sensitive_columns=6 max_rows=200
[ACCESS]   table=orders
[AUDIT]    time=2026-03-18T14:22:00Z status=SUCCESS rows=5 query="SELECT TOP 5 ..." error=""
[ACCESS]   table=users
[AUDIT]    time=2026-03-18T14:23:00Z status=BLOCKED rows=0 query="SELECT * FROM users" error="access to table 'users' is not permitted"
[SECURITY] masked sensitive column: salary
```

---

## 10. References

### 10.1 Official Documentation

- [MCP Protocol Specification](https://modelcontextprotocol.io/specification)
- [Claude Code Documentation](https://docs.anthropic.com/en/docs/claude-code/overview)
- [Claude Code Data Usage Policy](https://code.claude.com/docs/en/data-usage)
- [Anthropic Privacy Center (Commercial)](https://privacy.claude.com)
- [Anthropic Trust Center](https://trust.anthropic.com)
- [go-mssqldb Driver](https://github.com/microsoft/go-mssqldb)
- [mcp-go SDK](https://github.com/mark3labs/mcp-go)

### 10.2 Internal Documents

- SAM Platform Architecture — [internal wiki link]
- AURA AI Copilot Design Doc — [internal wiki link]
- BOSNET Integration Guide — [internal wiki link]
- Data Classification Policy — [internal wiki link]

---

> **Document Control**
>
> Version: 2.1 | Created: March 2026 | Status: Draft for Review
> Owner: Backend Engineering
>
> Changes from v1.0: Generic naming (`mcp-mssql`), blocklist approach, `.mcp-mssql-config.json` per-project config, `max_rows` configurable, `list_tables` queries real `INFORMATION_SCHEMA`, `[ACCESS]` logging added.
>
> Changes from v2.0: SQL injection fix in `describe_table` (parameterized query), keyword blocking uses regex word-boundary matching (no more false positives), `addRowLimitIfMissing` anchored to outermost SELECT only, added `ExecuteQueryParam` to `db.go`, Windows build/path notes added.
>
> Review cycle: Update when security model, config format, or Anthropic policy changes.
> Classification: Internal / Confidential — do not share externally.
