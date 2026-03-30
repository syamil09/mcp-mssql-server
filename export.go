package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Default export row limit (0 = unlimited). Can be overridden via config.
var ExportMaxRows = 10000

// ExportDirOverride allows config to override the default export directory.
var ExportDirOverride string

// Package-level compiled regexes
var (
	fromClauseRe    = regexp.MustCompile(`(?i)\bFROM\s+(?:\[?(\w+)\]?\.)?\[?(\w+)\]?`)
	validSPRe       = regexp.MustCompile(`^[\w.\[\]]+$`)
	safeFilenameRe  = regexp.MustCompile(`[^\w\-]`)
)

// validateAndExecSP validates a stored procedure is read-only and executes it.
// Shared between handleExecSP and handleExportJSON.
func validateAndExecSP(ctx context.Context, db *Database, procedure, params string) (*QueryResult, string, error) {
	if !validSPRe.MatchString(procedure) {
		return nil, "", fmt.Errorf("invalid procedure name")
	}

	inspectQuery := `
		SELECT m.definition
		FROM sys.sql_modules m
		JOIN sys.objects o ON m.object_id = o.object_id
		WHERE o.type = 'P'
		  AND (o.name = @p1 OR SCHEMA_NAME(o.schema_id) + '.' + o.name = @p1)
	`
	spName := procedure
	if parts := strings.Split(procedure, "."); len(parts) > 1 {
		spName = strings.Trim(parts[len(parts)-1], "[]")
	}

	defResult, err := db.ExecuteQueryParam(ctx, inspectQuery, spName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to inspect SP: %w", err)
	}
	if defResult.Count == 0 {
		return nil, "", fmt.Errorf("stored procedure '%s' not found or not accessible", procedure)
	}

	definition, _ := defResult.Rows[0]["definition"].(string)
	if definition == "" {
		return nil, "", fmt.Errorf("cannot read SP definition (may be encrypted)")
	}
	if err := ValidateSPDefinition(definition); err != nil {
		return nil, "", fmt.Errorf("SP blocked: %w", err)
	}

	execSQL := "EXEC " + procedure
	if strings.TrimSpace(params) != "" {
		execSQL += " " + params
	}

	log.Printf("[AUDIT] SP validated as read-only, executing: %s", execSQL)
	result, err := db.ExecuteQuery(ctx, execSQL)
	if err != nil {
		return nil, execSQL, fmt.Errorf("SP execution failed: %w", err)
	}

	return result, execSQL, nil
}

func handleExportJSON(db *Database) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		sqlQuery, _ := args["sql"].(string)
		procedure, _ := args["procedure"].(string)
		params, _ := args["params"].(string)
		jsonColumnsRaw, _ := args["json_columns"].(string)
		sourceColumn, _ := args["source_column"].(string)
		customFilename, _ := args["filename"].(string)

		sqlQuery = strings.TrimSpace(sqlQuery)
		procedure = strings.TrimSpace(procedure)
		sourceColumn = strings.TrimSpace(sourceColumn)

		// Validate: exactly one data source
		if sqlQuery == "" && procedure == "" {
			return mcp.NewToolResultError("either 'sql' or 'procedure' parameter is required"), nil
		}
		if sqlQuery != "" && procedure != "" {
			return mcp.NewToolResultError("provide either 'sql' or 'procedure', not both"), nil
		}

		// Parse explicit json_columns (case-insensitive)
		var jsonColumns map[string]bool
		if strings.TrimSpace(jsonColumnsRaw) != "" {
			jsonColumns = make(map[string]bool)
			for _, col := range strings.Split(jsonColumnsRaw, ",") {
				col = strings.TrimSpace(col)
				if col != "" {
					jsonColumns[strings.ToLower(col)] = true
				}
			}
		}

		// Execute the data source
		var result *QueryResult
		var sourceName string
		var auditLabel string

		if sqlQuery != "" {
			// SQL query mode
			if err := ValidateQuery(sqlQuery); err != nil {
				AuditLog("EXPORT: "+sqlQuery, false, 0, err)
				return mcp.NewToolResultError(fmt.Sprintf("Query blocked: %s", err.Error())), nil
			}

			// Apply row limit for export
			finalQuery := sqlQuery
			if ExportMaxRows > 0 {
				finalQuery = addRowLimitIfMissing(sqlQuery, ExportMaxRows)
			}

			var err error
			result, err = db.ExecuteQuery(ctx, finalQuery)
			if err != nil {
				AuditLog("EXPORT: "+sqlQuery, false, 0, err)
				return mcp.NewToolResultError(fmt.Sprintf("Query failed: %s", err.Error())), nil
			}
			sourceName = extractTableName(sqlQuery)
			auditLabel = "EXPORT: " + sqlQuery
		} else {
			// Stored procedure mode — shared validation
			var err error
			result, auditLabel, err = validateAndExecSP(ctx, db, procedure, params)
			auditLabel = "EXPORT: " + auditLabel
			if err != nil {
				AuditLog(auditLabel, false, 0, err)
				return mcp.NewToolResultError(err.Error()), nil
			}
			sourceName = extractSPName(procedure)
		}

		// Apply sensitive column masking
		result = MaskSensitiveColumns(result)

		// Validate source_column exists
		if sourceColumn != "" {
			found := false
			for _, col := range result.Columns {
				if strings.EqualFold(col, sourceColumn) {
					sourceColumn = col // normalize to actual case
					found = true
					break
				}
			}
			if !found {
				return mcp.NewToolResultError(fmt.Sprintf("source_column '%s' not found in result columns: %v", sourceColumn, result.Columns)), nil
			}
		}

		// Build the JSON output
		var outputData interface{}
		var exportCount int
		var skippedCount int

		if sourceColumn != "" {
			outputData, exportCount, skippedCount = buildSourceColumnOutput(result, sourceColumn)
		} else {
			outputData, exportCount = buildNormalOutput(result, jsonColumns)
		}

		// Generate filename
		filename := buildFilename(customFilename, sourceName)

		// Ensure output directory exists
		outDir := getExportDir()
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create output directory: %s", err.Error())), nil
		}

		// Build file path and validate no path traversal
		filePath := filepath.Join(outDir, filename)
		absOut, _ := filepath.Abs(outDir)
		absFile, _ := filepath.Abs(filePath)
		if !strings.HasPrefix(absFile, absOut+string(os.PathSeparator)) && absFile != absOut {
			return mcp.NewToolResultError("filename must not contain path traversal characters"), nil
		}

		// Write JSON file
		jsonBytes, err := json.MarshalIndent(outputData, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal JSON: %s", err.Error())), nil
		}

		if err := os.WriteFile(filePath, jsonBytes, 0644); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to write file: %s", err.Error())), nil
		}

		// Build response
		fileSize := formatFileSize(int64(len(jsonBytes)))

		AuditLog(auditLabel, true, exportCount, nil)

		summary := fmt.Sprintf("Exported successfully!\nFile: %s\nRows exported: %d\nFile size: %s", absFile, exportCount, fileSize)
		if skippedCount > 0 {
			summary += fmt.Sprintf("\nSkipped (invalid JSON): %d", skippedCount)
		}
		if exportCount == 0 {
			summary += "\nWarning: query returned 0 rows"
		}
		if ExportMaxRows > 0 && result.Count >= ExportMaxRows {
			summary += fmt.Sprintf("\nNote: result was limited to %d rows (export_max_rows setting)", ExportMaxRows)
		}

		log.Printf("[EXPORT] %s -> %s (%d rows, %s)", sourceName, absFile, exportCount, fileSize)
		return mcp.NewToolResultText(summary), nil
	}
}

// buildNormalOutput converts QueryResult rows to JSON-ready objects,
// parsing JSON columns as nested structures.
func buildNormalOutput(result *QueryResult, explicitJSONColumns map[string]bool) ([]map[string]interface{}, int) {
	rows := make([]map[string]interface{}, 0, len(result.Rows))

	for _, row := range result.Rows {
		outRow := make(map[string]interface{}, len(row))
		for key, val := range row {
			if shouldParseAsJSON(key, val, explicitJSONColumns) {
				if parsed, ok := tryParseJSON(val); ok {
					outRow[key] = parsed
					continue
				}
			}
			outRow[key] = val
		}
		rows = append(rows, outRow)
	}
	return rows, len(rows)
}

// buildSourceColumnOutput extracts JSON from a specific column across all rows.
func buildSourceColumnOutput(result *QueryResult, sourceColumn string) ([]interface{}, int, int) {
	output := make([]interface{}, 0) // non-nil so json.Marshal produces [] not null
	skipped := 0

	for _, row := range result.Rows {
		val, exists := row[sourceColumn]
		if !exists || val == nil {
			skipped++
			continue
		}

		str, ok := val.(string)
		if !ok {
			skipped++
			continue
		}

		str = strings.TrimSpace(str)
		if str == "" {
			skipped++
			continue
		}

		// Try parsing as JSON array first
		var arr []interface{}
		if err := json.Unmarshal([]byte(str), &arr); err == nil {
			output = append(output, arr...)
			continue
		}

		// Try parsing as JSON object
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(str), &obj); err == nil {
			output = append(output, obj)
			continue
		}

		skipped++
	}

	return output, len(output), skipped
}

// shouldParseAsJSON decides whether a column value should be parsed as nested JSON.
func shouldParseAsJSON(colName string, val interface{}, explicitColumns map[string]bool) bool {
	if explicitColumns != nil {
		// Case-insensitive: explicitColumns keys are already lowercased
		return explicitColumns[strings.ToLower(colName)]
	}
	// Auto-detect: check if string starts with { or [
	str, ok := val.(string)
	if !ok {
		return false
	}
	str = strings.TrimSpace(str)
	return len(str) > 0 && (str[0] == '{' || str[0] == '[')
}

// tryParseJSON attempts to parse a value as JSON. Returns the parsed result and success flag.
func tryParseJSON(val interface{}) (interface{}, bool) {
	str, ok := val.(string)
	if !ok {
		return nil, false
	}
	str = strings.TrimSpace(str)
	if str == "" {
		return nil, false
	}

	var parsed interface{}
	if err := json.Unmarshal([]byte(str), &parsed); err != nil {
		return nil, false
	}
	return parsed, true
}

// extractTableName extracts the first table/view name from a SQL query's FROM clause.
func extractTableName(sql string) string {
	matches := fromClauseRe.FindStringSubmatch(sql)
	if len(matches) >= 3 && matches[2] != "" {
		return matches[2]
	}
	return "export"
}

// extractSPName extracts the procedure name without schema prefix.
func extractSPName(procedure string) string {
	name := strings.ReplaceAll(procedure, "[", "")
	name = strings.ReplaceAll(name, "]", "")
	if parts := strings.Split(name, "."); len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return name
}

// buildFilename generates the output filename.
func buildFilename(custom, sourceName string) string {
	timestamp := time.Now().Format("20060102_150405")

	if custom != "" {
		// Strip path components to prevent traversal
		custom = filepath.Base(strings.TrimSpace(custom))
		if !strings.HasSuffix(strings.ToLower(custom), ".json") {
			custom += ".json"
		}
		return custom
	}

	if sourceName == "" {
		sourceName = "export"
	}

	safeName := safeFilenameRe.ReplaceAllString(sourceName, "_")
	return fmt.Sprintf("%s_%s.json", safeName, timestamp)
}

// getExportDir returns the absolute path to the export directory.
func getExportDir() string {
	// Priority 1: config override
	if ExportDirOverride != "" {
		return ExportDirOverride
	}
	// Priority 2: next to the executable
	exePath, err := os.Executable()
	if err == nil {
		return filepath.Join(filepath.Dir(exePath), "exportDatabaseSql")
	}
	// Fallback: current working directory
	return "exportDatabaseSql"
}

// formatFileSize returns a human-readable file size.
func formatFileSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
	)
	switch {
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
