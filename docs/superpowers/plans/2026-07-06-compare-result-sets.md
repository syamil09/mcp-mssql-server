# Compare Result Sets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Add two MCP tools - export_sql_to_csv for exporting query results to CSV, and compare_result_sets for deterministic cell-by-cell comparison between two query results (different connections, different queries, or same query before/after refactoring).

**Architecture:** Two new Go source files - csv_export.go for CSV export (reuses export.go execution logic), compare.go for comparison logic and handler. Both registered in tools.go. CSV uses encoding/csv. Comparison generates a structured JSON report saved to exportDatabaseSql/. The compare tool internally exports both sources to CSV before comparing.

**Tech Stack:** Go 1.25, encoding/csv, encoding/json, existing mcp-go framework.

**Global Constraints:**
- Follow existing tool registration pattern in tools.go (mcp.NewTool, WithDescription, WithString, handleFunc)
- Reuse resolveDB(), ValidateQuery(), validateAndExecSP() from existing code
- Reuse getExportDir(), formatFileSize() from export.go
- buildCSVFilename() in csv_export.go (shared by both tools)
- CSV output uses encoding/csv with all values as strings
- Comparison report saved as JSON to exportDatabaseSql/
- Both tools support multi-connection via connection param
- Path traversal protection on all filenames

---

### Task 1: Create csv_export.go - CSV Export Tool

**Files:**
- Create: csv_export.go (new file, ~150 lines)
- Modify: tools.go - register export_sql_to_csv tool

**Interfaces:**
- Consumes: ExecuteQuery, validateAndExecSP, ValidateQuery, MaskSensitiveColumns, getExportDir, formatFileSize, ExportMaxRows, resolveDB, AuditLog
- Produces: handleExportCSV handler, buildCSVFilename() helper, tool registration in registerTools()- [ ] **Step 1: Create csv_export.go with CSV export logic**

Create csv_export.go with handleExportCSV handler and buildCSVFilename() helper:

- handleExportCSV handler mirrors handleExportJSON pattern:
  - Accepts: sql, procedure, params, filename, connection
  - Executes via ValidateQuery + ExecuteQuery OR validateAndExecSP
  - Applies MaskSensitiveColumns
  - Writes CSV via encoding/csv Writer (header row + data rows)
  - Values formatted with fmt.Sprintf("%v", val), nil = empty string
  - Path traversal protection on filename
  - Returns summary: File path, Rows, Columns, File size

- buildCSVFilename(custom, sourceName string) string:
  - Custom name: append .csv if missing, strip path components
  - Default: <safeName>_<YYYYMMDD_HHmmss>.csv
  - Uses safeFilenameRe regex to sanitize sourceName

- [ ] **Step 2: Register export_sql_to_csv in tools.go**

Add to registerTools() after export_sql_to_json block:

Tool name: export_sql_to_csv
Params: sql (string), procedure (string), params (string), filename (string), connection (string)

- [ ] **Step 3: Build and verify it compiles**

Run: go build -o mcp-mssql.exe .
Expected: binary builds without errors

- [ ] **Step 4: Commit**

git add csv_export.go tools.go
git commit -m "feat: add export_sql_to_csv tool"

---### Task 2: Create compare.go - Comparison Logic & Tool

**Files:**
- Create: compare.go (new file, ~450 lines)
- Modify: tools.go - register compare_result_sets tool

**Interfaces:**
- Consumes: ExecuteQuery, validateAndExecSP, ValidateQuery, MaskSensitiveColumns, getExportDir, buildCSVFilename, formatFileSize, resolveDB, AuditLog
- Produces: handleCompareResults handler, comparison structs, compareResultSets(), writeCSVFile(), executeSource(), tool registration in registerTools()

**Output JSON format:**

```json
{
  "summary": {
    "timestamp": "2026-07-06T12:00:00Z",
    "match": false,
    "match_percent": 95.0,
    "row_count_a": 100,
    "row_count_b": 100
  },
  "columns": {
    "identical": true,
    "common": ["id", "name", "salary"],
    "only_in_a": [],
    "only_in_b": ["bonus"]
  },
  "rows": {
    "identical": 90,
    "different": 10,
    "only_in_a": 2,
    "only_in_b": 3
  },
  "differences": [
    {
      "row_index": 5,
      "key": {"id": 42},
      "columns": {
        "salary": {"a": 50000, "b": 55000},
        "status": {"a": "active", "b": "inactive"}
      }
    }
  ],
  "files": {
    "csv_a": "compare_sourceA_20260706_120000.csv",
    "csv_b": "compare_sourceB_20260706_120000.csv",
    "json": "compare_result_20260706_120000.json"
  }
}
```- [ ] **Step 1: Create compare.go with comparison logic**

**Go struct definitions:**

```go
type comparisonReport struct {
    Summary comparisonSummary `json:"summary"`
    Columns columnSection    `json:"columns"`
    Rows    rowSection       `json:"rows"`
    Diffs   []diffItem       `json:"differences,omitempty"`
    Files   filesSection     `json:"files"`
}

type comparisonSummary struct {
    Timestamp string  `json:"timestamp"`
    Match     bool    `json:"match"`
    MatchPct  float64 `json:"match_percent"`
    RowCountA int     `json:"row_count_a"`
    RowCountB int     `json:"row_count_b"`
}

type columnSection struct {
    Identical bool     `json:"identical"`
    Common    []string `json:"common"`
    OnlyInA   []string `json:"only_in_a"`
    OnlyInB   []string `json:"only_in_b"`
}

type rowSection struct {
    Identical int `json:"identical"`
    Different int `json:"different"`
    OnlyInA   int `json:"only_in_a"`
    OnlyInB   int `json:"only_in_b"`
}

type diffItem struct {
    RowIndex int               `json:"row_index"`
    Key      map[string]interface{} `json:"key,omitempty"`
    Columns  map[string]abPair `json:"columns"`
}

type abPair struct {
    A interface{} `json:"a"`
    B interface{} `json:"b"`
}

type filesSection struct {
    CsvA string `json:"csv_a,omitempty"`
    CsvB string `json:"csv_b,omitempty"`
    Json string `json:"json,omitempty"`
}
```**Key functions:**

- compareValues(a, b interface{}) bool — nil-safe, normalizes to string, tries numeric comparison via toFloat64() (float64/int/string numbers with comma stripping). Handles type differences like 50000 (int) vs "50000" (string).

- executeSource(ctx, db, cfg, sql, proc, params) — reuses ValidateQuery + ExecuteQuery OR validateAndExecSP, applies MaskSensitiveColumns. Returns (*QueryResult, sourceName, error).

- writeCSVFile(result *QueryResult, filePath string) error — writes header + data rows via encoding/csv. Uses strings.Builder to pre-allocate row capacity.

- compareResultSets(resultA, resultB, keyCol string) comparisonReport:
  1. summary: timestamp = time.Now().UTC().Format(time.RFC3339), row_count_a/b from result.Count
  2. columns: build sets from resultA.Columns and resultB.Columns, compute common and only_* via orderedDiff/orderedIntersect. identical = len(OnlyInA)==0 && len(OnlyInB)==0
  3. rows: identical/different/only counts via comparison logic
  4. diffs: iterate rows -
     Without keyCol: compare by index [i]
     With keyCol: build map from keyCol values, match by key
     For each diff: diffItem.RowIndex = i, diffItem.Columns = map[string]abPair{col: {A: valA, B: valB}}
     If keyCol: diffItem.Key = map[string]interface{}{keyCol: keyValue}
  5. match_percent: (totalCells - cellDiffs) / totalCells * 100, rounded to 2 decimals
  6. match: true only if match_percent == 100

**Handler handleCompareResults() flow:**

1. Extract: sql_a, procedure_a, params_a, connection_a, sql_b, procedure_b, params_b, connection_b, key_column, label_a, label_b, filename
2. Validate both sources have data
3. Resolve connections (getDB closure - default if empty)
4. Default labels: connection name or "Source A"/"Source B"
5. Execute source A -> resultA, sourceNameA (via executeSource)
6. Execute source B -> resultB, sourceNameB
7. Save both to CSV files in exportDatabaseSql/:
   csvPathA = getExportDir() / buildCSVFilename("", labelA)
   csvPathB = getExportDir() / buildCSVFilename("", labelB)
   writeCSVFile(resultA, csvPathA)
   writeCSVFile(resultB, csvPathB)
8. Run compareResultSets(resultA, resultB, keyCol) -> report
9. Set report.Files = {csv_a: csvPathA, csv_b: csvPathB}
10. Generate JSON filename: compare_<safeLabelA>_vs_<safeLabelB>_<timestamp>.json
11. Save report JSON to exportDatabaseSql/
12. Set report.Files.Json = savedPath
13. AuditLog + return report as JSON text- [ ] **Step 2: Register compare_result_sets in tools.go**

```go
s.AddTool(
    mcp.NewTool("compare_result_sets",
        mcp.WithDescription("Compare two result sets from SQL queries or stored procedures (possibly on different connections). Produces a deterministic cell-by-cell diff report. Internally exports both sources to CSV, compares, saves JSON to exportDatabaseSql/."),
        mcp.WithString("sql_a",
            mcp.Description("First SQL SELECT query. Mutually exclusive with 'procedure_a'.")),
        mcp.WithString("procedure_a",
            mcp.Description("First stored procedure. Mutually exclusive with 'sql_a'.")),
        mcp.WithString("params_a",
            mcp.Description("Parameters for first SP.")),
        mcp.WithString("connection_a",
            mcp.Description("Connection for source A. Uses default if omitted.")),
        mcp.WithString("sql_b",
            mcp.Description("Second SQL SELECT query. Mutually exclusive with 'procedure_b'.")),
        mcp.WithString("procedure_b",
            mcp.Description("Second stored procedure. Mutually exclusive with 'sql_b'.")),
        mcp.WithString("params_b",
            mcp.Description("Parameters for second SP.")),
        mcp.WithString("connection_b",
            mcp.Description("Connection for source B. Uses default if omitted.")),
        mcp.WithString("key_column",
            mcp.Description("Column name for matching rows (e.g. 'id'). Omit to compare by row index.")),
        mcp.WithString("label_a",
            mcp.Description("Label for source A (affects CSV filename). Default: connection name.")),
        mcp.WithString("label_b",
            mcp.Description("Label for source B (affects CSV filename). Default: connection name.")),
        mcp.WithString("filename",
            mcp.Description("Custom filename for JSON report (without extension). Default: compare_<labelA>_vs_<labelB>_<timestamp>.json")),
    ),
    handleCompareResults(cm),
)
```

- [ ] **Step 3: Build and verify it compiles**

Run: go build -o mcp-mssql.exe .
Expected: binary builds without errors

- [ ] **Step 4: Commit**

git add compare.go tools.go
git commit -m "feat: add compare_result_sets tool"

---### Task 3: Update main.go - Add Tool References in Instructions

**Files:**
- Modify: main.go - update server instructions to mention both new tools

- [ ] **Step 1: Read the instructions section in main.go**

Read main.go to find where the MCP server instructions string is defined.

- [ ] **Step 2: Add export_sql_to_csv and compare_result_sets to instructions**

Add both tools after the existing export_sql_to_json description, following existing format.

- [ ] **Step 3: Build and verify it compiles**

Run: go build -o mcp-mssql.exe .
Expected: binary builds without errors

- [ ] **Step 4: Commit**

git add main.go
git commit -m "docs: add new tools to server instructions"

---

### Task 4: Build and Final Verification

- [ ] **Step 1: Build the project**

Run: go build -o mcp-mssql.exe .
Expected: clean build, no warnings, exits with code 0

- [ ] **Step 2: Run go vet for static analysis**

Run: go vet ./...
Expected: no warnings

- [ ] **Step 3: Commit final changes**

git add -A
git commit -m "chore: finalize compare-result-sets implementation"

---

## Self-Review

**1. Spec coverage:**
- Task 1 covers export_sql_to_csv - standalone CSV export tool
- Task 2 covers compare_result_sets - integrated comparison with CSV export + JSON report + exact output format
- Task 3 covers updating server instructions
- Task 4 covers build verification

**2. Placeholder scan:**
- No "TBD", "TODO", "implement later" patterns
- All structs and functions have exact names and signatures defined
- Task descriptions include exact file paths

**3. Type consistency:**
- compareResultSets() returns comparisonReport matching user's exact JSON format
- diffItem.Columns uses map[string]abPair (not array) to match {"col": {"a": val, "b": val}}
- diffItem.Key uses map[string]interface{} to match {"id": 42}
- buildCSVFilename() shared between csv_export.go and compare.go
- All struct json tags match the user's expected field names

---

## Execution Handoff

**Plan complete and saved to docs/superpowers/plans/2026-07-06-compare-result-sets.md. Two execution options:**

1. Subagent-Driven (recommended) - I dispatch a fresh subagent per task, review between tasks, fast iteration

2. Inline Execution - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?