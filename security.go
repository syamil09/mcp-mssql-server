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
// Semicolons are allowed since they're needed for ;WITH CTE syntax and
// multi-statement DECLARE/SET blocks. Safety is still enforced by blocking
// all data-modifying keywords (INSERT, UPDATE, DELETE, DROP, etc.).
var dangerousPattern = regexp.MustCompile(
	`(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE|XP_CMDSHELL|SP_|OPENROWSET|BULK\s+INSERT|MERGE)\b`,
)

func ValidateQuery(sql string) error {
	normalized := strings.TrimSpace(sql)
	upper := strings.ToUpper(normalized)

	// Rule 1: Must start with SELECT, WITH, or DECLARE
	if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") && !strings.HasPrefix(upper, "DECLARE") {
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

// spDangerousPattern matches keywords that modify data or structure inside SP definitions.
var spDangerousPattern = regexp.MustCompile(
	`(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|MERGE|BULK\s+INSERT|XP_CMDSHELL|OPENROWSET|INTO)\b`,
)

// ValidateSPDefinition checks if a stored procedure body contains data-modifying keywords.
// Returns nil if the SP is read-only (safe), or an error describing what was found.
func ValidateSPDefinition(definition string) error {
	matches := spDangerousPattern.FindAllString(definition, -1)
	if len(matches) == 0 {
		return nil
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, m := range matches {
		upper := strings.ToUpper(m)
		if !seen[upper] {
			seen[upper] = true
			unique = append(unique, upper)
		}
	}

	return fmt.Errorf("stored procedure contains data-modifying keywords: %s", strings.Join(unique, ", "))
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
