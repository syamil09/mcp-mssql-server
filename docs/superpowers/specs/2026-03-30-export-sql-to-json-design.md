# Design: export_sql_to_json MCP Tool

## Purpose

Add a new MCP tool `export_sql_to_json` that exports SQL query or stored procedure results to JSON files, with support for nested JSON column parsing and single-column extraction mode.

## Parameters

| Param | Required | Type | Description |
|---|---|---|---|
| `sql` | no* | string | SQL SELECT query to execute |
| `procedure` | no* | string | Stored procedure name |
| `params` | no | string | SP parameters (same format as `exec_sp`) |
| `json_columns` | no | string | Comma-separated column names to force-parse as nested JSON. If omitted, auto-detect strings starting with `{` or `[` |
| `source_column` | no | string | Extract this single column's JSON content as the output list. Each row's value becomes a top-level JSON object in the output file |
| `filename` | no | string | Custom output filename (without extension). Default: `<source_name>_<timestamp>` |

*One of `sql` or `procedure` is required. Providing both is an error.

## Filename Convention

Default format: `<source_name>_<YYYYMMDD_HHmmss>.json`

Source name extraction:
- Stored procedure: strip schema prefix, use SP name. e.g. `dbo.SAM_API_GetProducts` -> `SAM_API_GetProducts`
- SQL query: extract first table/view name from FROM clause. e.g. `SELECT * FROM dbo.Products` -> `Products`
- Fallback if extraction fails: `export`

If `filename` param is provided, use it as-is (append `.json` if missing).

## Output Folder

Default: `exportDatabaseSql/` relative to the executable's directory. Created automatically on first use.

## Modes

### Normal mode (no `source_column`)

1. Execute query or SP -> get `QueryResult`
2. For each row, process JSON columns:
   - If `json_columns` provided: parse only those columns from string -> nested object
   - If `json_columns` omitted: auto-detect by checking if string value starts with `{` or `[`, then attempt `json.Unmarshal`
3. Write JSON array of all row objects to file
4. Return summary: file path, row count, file size

### Source column mode (`source_column` set)

1. Execute query or SP -> get `QueryResult`
2. For each row, extract the value of `source_column`
3. Parse each value as JSON (object or array)
   - If a value parses as a JSON array, flatten its elements into the output list
   - If a value parses as a JSON object, add it as one element
   - If a value fails to parse, skip it and count as error
4. Write flat JSON array of all collected objects to file
5. Return summary: file path, object count, skipped count, file size

## Validation

- Reuse existing `ValidateQuery()` for SQL input (read-only enforcement)
- Reuse existing SP inspection flow from `handleExecSP` (read-only definition check)
- One of `sql` or `procedure` must be provided, not both
- `source_column` must exist in the result columns if specified

## File Structure

- New file: `export.go` - contains `handleExportJSON()`, JSON column processing, filename extraction, file writing
- Registration: add to `registerTools()` in `tools.go`
- Server instructions: update instructions string in `main.go`

## Return Value

Tool returns text with:
- File path (absolute)
- Rows/objects exported
- File size (human-readable)
- Any warnings (skipped rows in source_column mode)

## Edge Cases

- Empty result set: write `[]` to file, return count=0
- `source_column` value is not valid JSON: skip row, include in warning count
- SQL extraction fails to find table name: use `export` as fallback name
- File already exists with same name: timestamp makes collision unlikely, but overwrite if it happens
