package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerTools(s *server.MCPServer, db *Database) {
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

		jsonBytes, err := json.MarshalIndent(safeResult, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("failed to serialize results"), nil
		}
		return mcp.NewToolResultText(string(jsonBytes)), nil
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
		jsonBytes, _ := json.MarshalIndent(safeResult, "", "  ")
		return mcp.NewToolResultText(string(jsonBytes)), nil
	}
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
