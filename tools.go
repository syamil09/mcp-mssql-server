package main

import (
	"context"
	"encoding/json"
	"fmt"
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
			mcp.WithDescription("Execute a SELECT query against the SQL Server database. Only SELECT and WITH (CTE) queries are allowed. Dangerous keywords are blocked. Results are automatically limited and sensitive columns are masked."),
			mcp.WithString("sql", mcp.Required(),
				mcp.Description("The SQL SELECT query to execute. Must start with SELECT or WITH.")),
		),
		handleQuery(db),
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
	finalQuery := addRowLimitIfMissing(query, MaxRows)

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
