package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerTools(s *server.MCPServer, db *Database) {
	s.AddTool(
		mcp.NewTool("benchmark_query",
			mcp.WithDescription("Benchmark one or two SQL queries and return only execution time and row count (no data). Useful for comparing query performance, e.g. old vs new version of a stored procedure or query refactoring. Only SELECT/WITH/DECLARE queries are allowed."),
			mcp.WithString("query_a", mcp.Required(),
				mcp.Description("The first SQL query to benchmark.")),
			mcp.WithString("query_b",
				mcp.Description("Optional second SQL query to compare against query_a.")),
			mcp.WithString("label_a",
				mcp.Description("Optional label for query_a (e.g. 'old version'). Default: 'Query A'.")),
			mcp.WithString("label_b",
				mcp.Description("Optional label for query_b (e.g. 'new version'). Default: 'Query B'.")),
		),
		handleBenchmark(db),
	)

	s.AddTool(
		mcp.NewTool("query_database",
			mcp.WithDescription("Execute a read-only SQL query against the SQL Server database. Supports SELECT, WITH (CTE), and DECLARE/SET variable blocks ending in SELECT. Semicolons are allowed for ;WITH CTE and multi-statement blocks. Data-modifying keywords (INSERT, UPDATE, DELETE, DROP, etc.) are blocked. Results are automatically limited and sensitive columns are masked. For stored procedures, use exec_sp instead."),
			mcp.WithString("sql", mcp.Required(),
				mcp.Description("The SQL query to execute. Must start with SELECT, WITH, or DECLARE.")),
		),
		handleQuery(db),
	)

	s.AddTool(
		mcp.NewTool("exec_sp",
			mcp.WithDescription("Execute a stored procedure after verifying it is read-only (contains no INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE, etc.). The SP definition is inspected from sys.sql_modules before execution. Use this when you need to call a stored procedure safely."),
			mcp.WithString("procedure", mcp.Required(),
				mcp.Description("The stored procedure name, e.g. 'dbo.SAM_API_GetDataProductBySalesman' or 'SAM_API_GetDataProductBySalesman'.")),
			mcp.WithString("params",
				mcp.Description("Parameters as SQL fragment, e.g. \"@szEmployeeId = '10002088', @dtDate = '2024-01-01'\". Leave empty if the SP takes no parameters.")),
		),
		handleExecSP(db),
	)

	s.AddTool(
		mcp.NewTool("list_tables",
			mcp.WithDescription("List all tables available for querying. Blocked tables are excluded from the list."),
		),
		handleListTables(db),
	)

	s.AddTool(
		mcp.NewTool("describe_table",
			mcp.WithDescription("Get column names and data types for a specific table. Blocked tables and sensitive columns are excluded."),
			mcp.WithString("table_name", mcp.Required(),
				mcp.Description("Name of the table to describe.")),
		),
		handleDescribeTable(db),
	)

	registerSSISTools(s, db)
}

func handleQuery(db *Database) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		sqlQuery, ok := args["sql"].(string)
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

		output, err := serializeResult(safeResult)
		if err != nil {
			return mcp.NewToolResultError("failed to serialize results"), nil
		}
		return mcp.NewToolResultText(output), nil
	}
}

func handleListTables(db *Database) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		result, err := db.ExecuteQuery(ctx,
			"SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_SCHEMA, TABLE_NAME",
		)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to list tables: %s", err.Error())), nil
		}

		var available []string
		for _, row := range result.Rows {
			schema := fmt.Sprintf("%v", row["TABLE_SCHEMA"])
			name := fmt.Sprintf("%v", row["TABLE_NAME"])
			nameLower := strings.ToLower(name)
			if !BlockedTables[nameLower] {
				available = append(available, fmt.Sprintf("%s.%s", schema, name))
			}
		}

		out := map[string]interface{}{
			"tables": available,
			"count":  len(available),
			"note":   "Blocked tables are excluded from this list.",
		}
		jsonBytes, _ := json.MarshalIndent(out, "", "  ")
		return mcp.NewToolResultText(string(jsonBytes)), nil
	}
}

func handleDescribeTable(db *Database) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		tableName, ok := args["table_name"].(string)
		if !ok {
			return mcp.NewToolResultError("table_name parameter is required"), nil
		}

		if BlockedTables[strings.ToLower(tableName)] {
			return mcp.NewToolResultError(fmt.Sprintf("table '%s' is not accessible", tableName)), nil
		}

		// Use parameterized query to prevent SQL injection.
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
		output, _ := serializeResult(safeResult)
		return mcp.NewToolResultText(output), nil
	}
}

func handleExecSP(db *Database) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		procedure, _ := args["procedure"].(string)
		procedure = strings.TrimSpace(procedure)
		if procedure == "" {
			return mcp.NewToolResultError("procedure parameter is required"), nil
		}

		// Sanitize: only allow alphanumeric, dot, underscore, brackets
		validSP := regexp.MustCompile(`^[\w.\[\]]+$`)
		if !validSP.MatchString(procedure) {
			return mcp.NewToolResultError("invalid procedure name"), nil
		}

		// Step 1: Read SP definition from sys.sql_modules
		inspectQuery := `
			SELECT m.definition
			FROM sys.sql_modules m
			JOIN sys.objects o ON m.object_id = o.object_id
			WHERE o.type = 'P'
			  AND (o.name = @p1 OR SCHEMA_NAME(o.schema_id) + '.' + o.name = @p1)
		`
		// Extract just the object name (without schema) for the name-only match
		spName := procedure
		if parts := strings.Split(procedure, "."); len(parts) > 1 {
			spName = strings.Trim(parts[len(parts)-1], "[]")
		}

		defResult, err := db.ExecuteQueryParam(ctx, inspectQuery, spName)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to inspect SP: %s", err.Error())), nil
		}

		if defResult.Count == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("stored procedure '%s' not found or not accessible", procedure)), nil
		}

		definition, _ := defResult.Rows[0]["definition"].(string)
		if definition == "" {
			return mcp.NewToolResultError("cannot read SP definition (may be encrypted)"), nil
		}

		// Step 2: Validate the SP body is read-only
		if err := ValidateSPDefinition(definition); err != nil {
			AuditLog("EXEC "+procedure, false, 0, err)
			return mcp.NewToolResultError(fmt.Sprintf("SP blocked: %s", err.Error())), nil
		}

		// Step 3: Build and execute
		execSQL := "EXEC " + procedure
		params, _ := args["params"].(string)
		if strings.TrimSpace(params) != "" {
			execSQL += " " + params
		}

		log.Printf("[AUDIT] SP validated as read-only, executing: %s", execSQL)

		result, err := db.ExecuteQuery(ctx, execSQL)
		if err != nil {
			AuditLog(execSQL, false, 0, err)
			return mcp.NewToolResultError(fmt.Sprintf("SP execution failed: %s", err.Error())), nil
		}

		safeResult := MaskSensitiveColumns(result)
		AuditLog(execSQL, true, safeResult.Count, nil)

		output, err := serializeResult(safeResult)
		if err != nil {
			return mcp.NewToolResultError("failed to serialize results"), nil
		}
		return mcp.NewToolResultText(output), nil
	}
}

func handleBenchmark(db *Database) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		queryA, _ := args["query_a"].(string)
		if strings.TrimSpace(queryA) == "" {
			return mcp.NewToolResultError("query_a parameter is required"), nil
		}

		labelA, _ := args["label_a"].(string)
		if labelA == "" {
			labelA = "Query A"
		}

		// Validate and run query A
		if err := ValidateQuery(queryA); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("%s blocked: %s", labelA, err.Error())), nil
		}

		resultA, err := runBenchmark(ctx, db, queryA)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("%s failed: %s", labelA, err.Error())), nil
		}
		resultA["label"] = labelA

		results := []map[string]interface{}{resultA}

		// If query_b is provided, benchmark it too
		queryB, _ := args["query_b"].(string)
		if strings.TrimSpace(queryB) != "" {
			labelB, _ := args["label_b"].(string)
			if labelB == "" {
				labelB = "Query B"
			}

			if err := ValidateQuery(queryB); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("%s blocked: %s", labelB, err.Error())), nil
			}

			resultB, err := runBenchmark(ctx, db, queryB)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("%s failed: %s", labelB, err.Error())), nil
			}
			resultB["label"] = labelB

			results = append(results, resultB)

			// Add comparison
			durA := resultA["duration_ms"].(float64)
			durB := resultB["duration_ms"].(float64)
			comparison := map[string]interface{}{
				"faster":       labelA,
				"diff_ms":      durB - durA,
				"diff_percent": fmt.Sprintf("%.1f%%", ((durB-durA)/durA)*100),
			}
			if durB < durA {
				comparison["faster"] = labelB
				comparison["diff_ms"] = durA - durB
				comparison["diff_percent"] = fmt.Sprintf("%.1f%%", ((durA-durB)/durB)*100)
			}

			out := map[string]interface{}{
				"benchmarks": results,
				"comparison": comparison,
			}
			jsonBytes, _ := json.MarshalIndent(out, "", "  ")
			return mcp.NewToolResultText(string(jsonBytes)), nil
		}

		jsonBytes, _ := json.MarshalIndent(resultA, "", "  ")
		return mcp.NewToolResultText(string(jsonBytes)), nil
	}
}

func runBenchmark(ctx context.Context, db *Database, query string) (map[string]interface{}, error) {
	// No row limit for benchmarking — run the query as-is for accurate timing
	finalQuery := query

	start := time.Now()
	result, err := db.ExecuteQuery(ctx, finalQuery)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"row_count":   result.Count,
		"columns":     result.Columns,
		"duration_ms": float64(duration.Microseconds()) / 1000.0,
		"duration":    duration.String(),
	}, nil
}

// serializeResult converts a QueryResult to the configured output format (JSON or TOON).
func serializeResult(result *QueryResult) (string, error) {
	if OutputFormat == "toon" {
		return result.ToTOON(), nil
	}
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// addRowLimitIfMissing injects TOP N into the outermost SELECT only.
var selectAtStart = regexp.MustCompile(`(?i)^(\s*(?:WITH\s+.+?\)\s+)?SELECT)\s`)

func addRowLimitIfMissing(query string, limit int) string {
	upper := strings.ToUpper(strings.TrimSpace(query))
	if strings.Contains(upper, "TOP ") || strings.Contains(upper, "FETCH NEXT") {
		return query
	}
	loc := selectAtStart.FindStringIndex(query)
	if loc == nil {
		return query
	}
	insertPos := loc[1] - 1
	return query[:insertPos] + fmt.Sprintf(" TOP %d", limit) + query[insertPos:]
}
