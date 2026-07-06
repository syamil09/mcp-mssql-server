package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func handleExportCSV(cm *ConnectionManager) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		db, connCfg, err := resolveDB(cm, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		args := req.GetArguments()

		sqlQuery, _ := args["sql"].(string)
		procedure, _ := args["procedure"].(string)
		params, _ := args["params"].(string)
		customFilename, _ := args["filename"].(string)

		sqlQuery = strings.TrimSpace(sqlQuery)
		procedure = strings.TrimSpace(procedure)

		if sqlQuery == "" && procedure == "" {
			return mcp.NewToolResultError("either 'sql' or 'procedure' parameter is required"), nil
		}
		if sqlQuery != "" && procedure != "" {
			return mcp.NewToolResultError("provide either 'sql' or 'procedure', not both"), nil
		}

		var result *QueryResult
		var sourceName string
		var auditLabel string

		if sqlQuery != "" {
			if err := ValidateQuery(sqlQuery, connCfg.BlockedTablesMap); err != nil {
				AuditLog("EXPORT_CSV: "+sqlQuery, false, 0, err)
				return mcp.NewToolResultError(fmt.Sprintf("Query blocked: %s", err.Error())), nil
			}

			finalQuery := sqlQuery
			if ExportMaxRows > 0 {
				finalQuery = addRowLimitIfMissing(sqlQuery, ExportMaxRows)
			}

			result, err = db.ExecuteQuery(ctx, finalQuery)
			if err != nil {
				AuditLog("EXPORT_CSV: "+sqlQuery, false, 0, err)
				return mcp.NewToolResultError(fmt.Sprintf("Query failed: %s", err.Error())), nil
			}
			sourceName = extractTableName(sqlQuery)
			auditLabel = "EXPORT_CSV: " + sqlQuery
		} else {
			result, auditLabel, err = validateAndExecSP(ctx, db, procedure, params)
			auditLabel = "EXPORT_CSV: " + auditLabel
			if err != nil {
				AuditLog(auditLabel, false, 0, err)
				return mcp.NewToolResultError(err.Error()), nil
			}
			sourceName = extractSPName(procedure)
		}

		result = MaskSensitiveColumns(result, connCfg.SensitiveColumnsMap)

		filename := buildCSVFilename(customFilename, sourceName)

		outDir := getExportDir()
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create output directory: %s", err.Error())), nil
		}

		filePath := filepath.Join(outDir, filename)
		absOut, _ := filepath.Abs(outDir)
		absFile, _ := filepath.Abs(filePath)
		if !strings.HasPrefix(absFile, absOut+string(os.PathSeparator)) && absFile != absOut {
			return mcp.NewToolResultError("filename must not contain path traversal characters"), nil
		}

		if err := writeCSVFile(result, filePath); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to write CSV: %s", err.Error())), nil
		}

		fileInfo, _ := os.Stat(filePath)
		fileSize := formatFileSize(fileInfo.Size())

		AuditLog(auditLabel, true, result.Count, nil)

		summary := fmt.Sprintf("Exported successfully!\nFile: %s\nRows: %d\nColumns: %d\nFile size: %s", absFile, result.Count, len(result.Columns), fileSize)
		if ExportMaxRows > 0 && result.Count >= ExportMaxRows {
			summary += fmt.Sprintf("\nNote: result was limited to %d rows (export_max_rows setting)", ExportMaxRows)
		}
		if result.Count == 0 {
			summary += "\nWarning: query returned 0 rows"
		}

		log.Printf("[EXPORT_CSV] %s -> %s (%d rows, %s)", sourceName, absFile, result.Count, fileSize)
		return mcp.NewToolResultText(summary), nil
	}
}

func buildCSVFilename(custom, sourceName string) string {
	if custom != "" {
		custom = filepath.Base(strings.TrimSpace(custom))
		if !strings.HasSuffix(strings.ToLower(custom), ".csv") {
			custom += ".csv"
		}
		return custom
	}

	if sourceName == "" {
		sourceName = "export"
	}

	safeName := safeFilenameRe.ReplaceAllString(sourceName, "_")
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s.csv", safeName, timestamp)
}

func writeCSVFile(result *QueryResult, filePath string) error {
	csvFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	if err := writer.Write(result.Columns); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	var stringRow []string
	for _, row := range result.Rows {
		stringRow = stringRow[:0]
		for _, col := range result.Columns {
			val := row[col]
			if val == nil {
				stringRow = append(stringRow, "")
			} else {
				stringRow = append(stringRow, fmt.Sprintf("%v", val))
			}
		}
		if err := writer.Write(stringRow); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	return writer.Error()
}
