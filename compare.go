package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

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
	MatchPct  float64  `json:"match_percent"`
	RowCountA int      `json:"row_count_a"`
	RowCountB int      `json:"row_count_b"`
	Warnings  []string `json:"warnings,omitempty"`
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
	RowIndex int                    `json:"row_index"`
	Key      map[string]interface{} `json:"key,omitempty"`
	Columns  map[string]abPair      `json:"columns"`
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

func compareValues(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	strA := fmt.Sprintf("%v", a)
	strB := fmt.Sprintf("%v", b)

	var fA, fB float64
	isNumA, isNumB := false, false
	if nA, err := toFloat64(a); err == nil {
		fA = nA
		isNumA = true
	}
	if nB, err := toFloat64(b); err == nil {
		fB = nB
		isNumB = true
	}
	if isNumA && isNumB {
		return fA == fB
	}

	return strA == strB
}

func toFloat64(v interface{}) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case float32:
		return float64(val), nil
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case string:
		s := strings.TrimSpace(val)
		s = strings.ReplaceAll(s, ",", "")
		if s == "" {
			return 0, fmt.Errorf("empty string")
		}
		var f float64
		if _, err := fmt.Sscanf(s, "%f", &f); err != nil {
			return 0, err
		}
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return 0, fmt.Errorf("invalid number")
		}
		return f, nil
	default:
		return 0, fmt.Errorf("not a number")
	}
}

func orderedDiff(list []string, set map[string]bool) []string {
	var out []string
	for _, s := range list {
		if !set[s] {
			out = append(out, s)
		}
	}
	return out
}

func orderedIntersect(a, b []string) []string {
	setB := make(map[string]bool)
	for _, s := range b {
		setB[s] = true
	}
	var out []string
	for _, s := range a {
		if setB[s] {
			out = append(out, s)
		}
	}
	return out
}

func findDuplicateKeys(result *QueryResult, keyCol string) map[string]int {
	counts := make(map[string]int)
	for _, row := range result.Rows {
		key := fmt.Sprintf("%v", row[keyCol])
		counts[key]++
	}
	dups := make(map[string]int)
	for k, c := range counts {
		if c > 1 {
			dups[k] = c
		}
	}
	return dups
}

func executeSource(ctx context.Context, db *Database, connCfg *ConnectionConfig, sql, procedure, params string) (*QueryResult, string, error) {
	if sql != "" && procedure != "" {
		return nil, "", fmt.Errorf("provide either sql or procedure, not both")
	}

	if sql != "" {
		if err := ValidateQuery(sql, connCfg.BlockedTablesMap); err != nil {
			return nil, "", fmt.Errorf("query blocked: %s", err.Error())
		}

		finalQuery := sql
		if ExportMaxRows > 0 {
			finalQuery = addRowLimitIfMissing(sql, ExportMaxRows)
		}

		result, err := db.ExecuteQuery(ctx, finalQuery)
		if err != nil {
			return nil, "", fmt.Errorf("query failed: %s", err.Error())
		}

		sourceName := extractTableName(sql)
		return MaskSensitiveColumns(result, connCfg.SensitiveColumnsMap), sourceName, nil
	}

	result, auditLabel, err := validateAndExecSP(ctx, db, procedure, params)
	if err != nil {
		return nil, "", err
	}
	_ = auditLabel
	sourceName := extractSPName(procedure)
	return MaskSensitiveColumns(result, connCfg.SensitiveColumnsMap), sourceName, nil
}

func compareResultSets(resultA, resultB *QueryResult, keyCol string) comparisonReport {
	var report comparisonReport

	report.Summary.Timestamp = time.Now().UTC().Format(time.RFC3339)
	report.Summary.RowCountA = resultA.Count
	report.Summary.RowCountB = resultB.Count

	colSetA := make(map[string]bool)
	colSetB := make(map[string]bool)
	for _, c := range resultA.Columns {
		colSetA[c] = true
	}
	for _, c := range resultB.Columns {
		colSetB[c] = true
	}

	report.Columns.OnlyInA = orderedDiff(resultA.Columns, colSetB)
	report.Columns.OnlyInB = orderedDiff(resultB.Columns, colSetA)
	report.Columns.Common = orderedIntersect(resultA.Columns, resultB.Columns)
	report.Columns.Identical = len(report.Columns.OnlyInA) == 0 && len(report.Columns.OnlyInB) == 0

	commonCols := report.Columns.Common

	if keyCol != "" {
		dupsA := findDuplicateKeys(resultA, keyCol)
		dupsB := findDuplicateKeys(resultB, keyCol)

		if len(dupsA) > 0 || len(dupsB) > 0 {
			for k, c := range dupsA {
				report.Summary.Warnings = append(report.Summary.Warnings,
					fmt.Sprintf("Key column '%s' is not unique in source A: value '%s' appears %d time(s)", keyCol, k, c))
			}
			for k, c := range dupsB {
				report.Summary.Warnings = append(report.Summary.Warnings,
					fmt.Sprintf("Key column '%s' is not unique in source B: value '%s' appears %d time(s)", keyCol, k, c))
			}
			report.Summary.Warnings = append(report.Summary.Warnings,
				"Fell back to index-based comparison. Use a unique key column for reliable row matching.")

			diffs, idents, onlyA, onlyB := compareByIndex(resultA, resultB, commonCols)
			report.Diffs = diffs
			report.Rows.Identical = idents
			report.Rows.Different = len(diffs)
			report.Rows.OnlyInA = onlyA
			report.Rows.OnlyInB = onlyB
		} else {
			diffs, idents, onlyA, onlyB := compareByKey(resultA, resultB, keyCol, commonCols)
			report.Diffs = diffs
			report.Rows.Identical = idents
			report.Rows.Different = len(diffs)
			report.Rows.OnlyInA = onlyA
			report.Rows.OnlyInB = onlyB
		}
	} else {
		diffs, idents, onlyA, onlyB := compareByIndex(resultA, resultB, commonCols)
		report.Diffs = diffs
		report.Rows.Identical = idents
		report.Rows.Different = len(diffs)
		report.Rows.OnlyInA = onlyA
		report.Rows.OnlyInB = onlyB
	}

	totalCells := resultA.Count * len(commonCols)
	if totalCells == 0 || report.Summary.RowCountA == 0 {
		report.Summary.MatchPct = 100.0
	} else {
		cellDiffs := 0
		for _, d := range report.Diffs {
			cellDiffs += len(d.Columns)
		}
		report.Summary.MatchPct = math.Round(float64(totalCells-cellDiffs)/float64(totalCells)*10000) / 100
	}
	report.Summary.Match = report.Summary.MatchPct == 100.0 &&
		report.Summary.RowCountA == report.Summary.RowCountB &&
		len(report.Columns.OnlyInA) == 0 &&
		len(report.Columns.OnlyInB) == 0

	return report
}

func compareByIndex(resultA, resultB *QueryResult, commonCols []string) (diffs []diffItem, identical, onlyInA, onlyInB int) {
	maxRows := resultA.Count
	if resultB.Count > maxRows {
		maxRows = resultB.Count
	}

	identical = 0
	onlyInA = 0
	onlyInB = 0

	for i := 0; i < maxRows; i++ {
		if i >= resultA.Count {
			rd := diffItem{RowIndex: i, Columns: make(map[string]abPair)}
			diffs = append(diffs, rd)
			onlyInB++
			continue
		}
		if i >= resultB.Count {
			rd := diffItem{RowIndex: i, Columns: make(map[string]abPair)}
			diffs = append(diffs, rd)
			onlyInA++
			continue
		}

		rowA := resultA.Rows[i]
		rowB := resultB.Rows[i]

		var changed map[string]abPair
		for _, col := range commonCols {
			valA := rowA[col]
			valB := rowB[col]
			if !compareValues(valA, valB) {
				if changed == nil {
					changed = make(map[string]abPair)
				}
				changed[col] = abPair{A: valA, B: valB}
			}
		}

		if len(changed) > 0 {
			diffs = append(diffs, diffItem{RowIndex: i, Columns: changed})
		} else {
			identical++
		}
	}

	return
}

func compareByKey(resultA, resultB *QueryResult, keyCol string, commonCols []string) (diffs []diffItem, identical, onlyInA, onlyInB int) {
	buildMap := func(result *QueryResult) map[string]map[string]interface{} {
		m := make(map[string]map[string]interface{}, result.Count)
		for _, row := range result.Rows {
			key := fmt.Sprintf("%v", row[keyCol])
			m[key] = row
		}
		return m
	}

	mapA := buildMap(resultA)
	mapB := buildMap(resultB)

	seen := make(map[string]bool)
	index := 0

	for key, rowA := range mapA {
		rowB, exists := mapB[key]
		if !exists {
			diffs = append(diffs, diffItem{
				RowIndex: index,
				Key:      map[string]interface{}{keyCol: key},
				Columns:  make(map[string]abPair),
			})
			onlyInA++
			index++
			continue
		}
		seen[key] = true

		var changed map[string]abPair
		for _, col := range commonCols {
			valA := rowA[col]
			valB := rowB[col]
			if !compareValues(valA, valB) {
				if changed == nil {
					changed = make(map[string]abPair)
				}
				changed[col] = abPair{A: valA, B: valB}
			}
		}

		if len(changed) > 0 {
			diffs = append(diffs, diffItem{
				RowIndex: index,
				Key:      map[string]interface{}{keyCol: key},
				Columns:  changed,
			})
		} else {
			identical++
		}
		index++
	}

	for key := range mapB {
		if !seen[key] {
			diffs = append(diffs, diffItem{
				RowIndex: index,
				Key:      map[string]interface{}{keyCol: key},
				Columns:  make(map[string]abPair),
			})
			onlyInB++
			index++
		}
	}

	return
}

func handleCompareResults(cm *ConnectionManager) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()

		sqlA, _ := args["sql_a"].(string)
		procA, _ := args["procedure_a"].(string)
		paramsA, _ := args["params_a"].(string)
		connA, _ := args["connection_a"].(string)

		sqlB, _ := args["sql_b"].(string)
		procB, _ := args["procedure_b"].(string)
		paramsB, _ := args["params_b"].(string)
		connB, _ := args["connection_b"].(string)

		keyColumn, _ := args["key_column"].(string)
		labelA, _ := args["label_a"].(string)
		labelB, _ := args["label_b"].(string)
		customFilename, _ := args["filename"].(string)

		hasSource := func(sql, proc string) bool {
			return strings.TrimSpace(sql) != "" || strings.TrimSpace(proc) != ""
		}
		if !hasSource(sqlA, procA) {
			return mcp.NewToolResultError("source A requires either 'sql_a' or 'procedure_a' parameter"), nil
		}
		if !hasSource(sqlB, procB) {
			return mcp.NewToolResultError("source B requires either 'sql_b' or 'procedure_b' parameter"), nil
		}

		resolveConn := func(connName string) (*Database, *ConnectionConfig, error) {
			if connName == "" {
				return resolveDB(cm, req)
			}
			db, cfg, err := cm.GetConnection(connName)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to connect to '%s': %w", connName, err)
			}
			return db, cfg, nil
		}

		dbA, cfgA, err := resolveConn(connA)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("source A connection: %s", err.Error())), nil
		}
		dbB, cfgB, err := resolveConn(connB)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("source B connection: %s", err.Error())), nil
		}

		if labelA == "" {
			labelA = "Source_A"
			if connA != "" {
				labelA = strings.ReplaceAll(connA, " ", "_")
			}
		}
		if labelB == "" {
			labelB = "Source_B"
			if connB != "" {
				labelB = strings.ReplaceAll(connB, " ", "_")
			}
		}

		resultA, _, err := executeSource(ctx, dbA, cfgA, sqlA, procA, paramsA)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Source A failed: %s", err.Error())), nil
		}
		resultB, _, err := executeSource(ctx, dbB, cfgB, sqlB, procB, paramsB)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Source B failed: %s", err.Error())), nil
		}

		outDir := getExportDir()
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create output directory: %s", err.Error())), nil
		}

		csvPathA := filepath.Join(outDir, buildCSVFilename("", labelA))
		csvPathB := filepath.Join(outDir, buildCSVFilename("", labelB))

		if err := writeCSVFile(resultA, csvPathA); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to write CSV A: %s", err.Error())), nil
		}
		if err := writeCSVFile(resultB, csvPathB); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to write CSV B: %s", err.Error())), nil
		}

		report := compareResultSets(resultA, resultB, keyColumn)

		absOut, _ := filepath.Abs(outDir)
		report.Files.CsvA = filepath.Join(absOut, filepath.Base(csvPathA))
		report.Files.CsvB = filepath.Join(absOut, filepath.Base(csvPathB))

		jsonName := customFilename
		if jsonName == "" {
			safeLabelA := safeFilenameRe.ReplaceAllString(labelA, "_")
			safeLabelB := safeFilenameRe.ReplaceAllString(labelB, "_")
			timestamp := time.Now().Format("20060102_150405")
			jsonName = fmt.Sprintf("compare_%s_vs_%s_%s.json", safeLabelA, safeLabelB, timestamp)
		} else {
			jsonName = filepath.Base(jsonName)
			if !strings.HasSuffix(strings.ToLower(jsonName), ".json") {
				jsonName += ".json"
			}
		}

		jsonPath := filepath.Join(outDir, jsonName)
		absFile, _ := filepath.Abs(jsonPath)
		if !strings.HasPrefix(absFile, absOut+string(os.PathSeparator)) && absFile != absOut {
			return mcp.NewToolResultError("filename must not contain path traversal characters"), nil
		}

		jsonBytes, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal report: %s", err.Error())), nil
		}

		if err := os.WriteFile(jsonPath, jsonBytes, 0644); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to write report: %s", err.Error())), nil
		}

		report.Files.Json = absFile

		AuditLog(fmt.Sprintf("COMPARE: %s vs %s", labelA, labelB), true, resultA.Count+resultB.Count, nil)
		log.Printf("[COMPARE] %s vs %s -> %s (match: %.2f%%)", labelA, labelB, absFile, report.Summary.MatchPct)

		finalReport, _ := json.MarshalIndent(report, "", "  ")
		return mcp.NewToolResultText(string(finalReport)), nil
	}
}
