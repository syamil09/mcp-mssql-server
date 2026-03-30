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

// spDangerousPattern matches keywords that modify data/structure or enable dynamic SQL in SP definitions.
// EXEC/EXECUTE/SP_EXECUTESQL are blocked because dynamic SQL can bypass all static checks.
// Note: INTO is checked separately only when NOT targeting temp tables.
var spDangerousPattern = regexp.MustCompile(
	`(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|MERGE|BULK\s+INSERT|XP_CMDSHELL|OPENROWSET|EXEC|EXECUTE|SP_EXECUTESQL|INTO)\b`,
)

// Pre-compiled regexes for stripSafeSPPatterns to avoid recompilation per call.
var (
	reLineComment   = regexp.MustCompile(`--[^\n]*`)
	reBlockComment  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reStringLiteral = regexp.MustCompile(`'[^']*'`)
	reSPHeader      = regexp.MustCompile(`(?is)\b(CREATE|ALTER)\s+(PROCEDURE|PROC|FUNCTION)\b`)
	reTempTableDef  = regexp.MustCompile(`(?i)(?:CREATE\s+TABLE|INTO)\s+(#\w+)`)
	reTempAlias     = regexp.MustCompile(`(?i)(?:FROM|JOIN)\s+#\w+\s+(?:WITH\s*\([^)]*\)\s+)?(\w+)`)
	reInsertTemp    = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+#\w+`)
	reIntoTemp      = regexp.MustCompile(`(?is)\bINTO\s+#\w+`)
	reCreateTable   = regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+#\w+`)
	reCreateIndex   = regexp.MustCompile(`(?is)\bCREATE\s+INDEX\s+\w+\s+ON\s+#\w+`)
	reDropTable     = regexp.MustCompile(`(?is)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?#\w+`)
	reDropIfObj     = regexp.MustCompile(`(?is)\bIF\s+OBJECT_ID\s*\(\s*'tempdb\.\.#\w+'\s*\)\s*IS\s+NOT\s+NULL\s+DROP\s+TABLE\s+#\w+`)
	reTruncateTemp  = regexp.MustCompile(`(?is)\bTRUNCATE\s+TABLE\s+#\w+`)
	reAlterTemp     = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+#\w+`)
	reDeleteTemp    = regexp.MustCompile(`(?is)\bDELETE\s+FROM\s+#\w+`)
	reUpdateTemp    = regexp.MustCompile(`(?is)\bUPDATE\s+#\w+`)
)

// stripSafeSPPatterns removes comments, string literals, SP header, and all temp table
// operations (including aliased references like UPDATE sd FROM #storeData sd) so they
// don't trigger false positives in the dangerous keyword check.
func stripSafeSPPatterns(definition string) string {
	// Step 1: Strip SQL comments (-- line comments and /* block comments */)
	// This prevents keywords in comments from triggering false positives.
	result := reLineComment.ReplaceAllString(definition, "")
	result = reBlockComment.ReplaceAllString(result, "")

	// Step 2: Strip string literals to prevent false positives from keywords
	// inside strings (e.g., 'Actual vs Target' won't match INTO).
	// Save originals for alias extraction first.
	withStrings := result
	result = reStringLiteral.ReplaceAllString(result, "''")

	// Step 3: Strip the SP header (CREATE/ALTER PROCEDURE/PROC/FUNCTION)
	result = reSPHeader.ReplaceAllString(result, "")

	// Step 4: Collect all temp table names defined in this SP
	// Matches: CREATE TABLE #xxx, INTO #xxx (from SELECT INTO or INSERT INTO)
	// Use the version with strings intact so table names inside strings aren't missed.
	tempNames := map[string]bool{}
	for _, m := range reTempTableDef.FindAllStringSubmatch(withStrings, -1) {
		tempNames[strings.ToUpper(m[1])] = true
	}

	// Step 5: Collect aliases for temp tables
	// Patterns: FROM #table alias, JOIN #table alias (with optional WITH(NOLOCK))
	tempAliases := map[string]bool{}
	for _, m := range reTempAlias.FindAllStringSubmatch(withStrings, -1) {
		alias := strings.ToUpper(m[1])
		// Skip SQL keywords that look like aliases
		if !isSQLKeyword(alias) {
			tempAliases[alias] = true
		}
	}

	if len(tempNames) == 0 {
		return result
	}

	// Step 6: Strip DML/DDL that directly targets temp tables (#name)
	result = reInsertTemp.ReplaceAllString(result, "")
	result = reIntoTemp.ReplaceAllString(result, "")
	result = reCreateTable.ReplaceAllString(result, "")
	result = reCreateIndex.ReplaceAllString(result, "")
	result = reDropIfObj.ReplaceAllString(result, "") // must come before reDropTable (more specific)
	result = reDropTable.ReplaceAllString(result, "")
	result = reTruncateTemp.ReplaceAllString(result, "")
	result = reAlterTemp.ReplaceAllString(result, "")
	result = reDeleteTemp.ReplaceAllString(result, "")
	result = reUpdateTemp.ReplaceAllString(result, "")

	// Step 7: Strip DML targeting temp table aliases (e.g., UPDATE sd SET ... FROM #storeData sd)
	for alias := range tempAliases {
		quotedAlias := regexp.QuoteMeta(alias)
		// UPDATE alias SET
		result = regexp.MustCompile(`(?is)\bUPDATE\s+` + quotedAlias + `\b`).ReplaceAllString(result, "")
		// DELETE alias FROM
		result = regexp.MustCompile(`(?is)\bDELETE\s+` + quotedAlias + `\b`).ReplaceAllString(result, "")
	}

	return result
}

// isSQLKeyword returns true if the word is a common SQL keyword (not a table alias).
var sqlKeywords = map[string]bool{
	"ON": true, "WHERE": true, "SET": true, "AND": true, "OR": true,
	"AS": true, "IN": true, "NOT": true, "NULL": true, "IS": true,
	"LEFT": true, "RIGHT": true, "INNER": true, "OUTER": true, "CROSS": true,
	"FULL": true, "INTO": true, "FROM": true, "JOIN": true, "SELECT": true,
	"WITH": true, "NOLOCK": true, "ORDER": true, "BY": true, "GROUP": true,
	"HAVING": true, "UNION": true, "ALL": true, "TOP": true, "DISTINCT": true,
	"CASE": true, "WHEN": true, "THEN": true, "ELSE": true, "END": true,
	"EXISTS": true, "BETWEEN": true, "LIKE": true, "VALUES": true,
}

func isSQLKeyword(word string) bool {
	return sqlKeywords[strings.ToUpper(word)]
}

// ValidateSPDefinition checks if a stored procedure body contains data-modifying keywords.
// The SP header (CREATE PROCEDURE) and temp table operations (#table) are stripped first
// since they are safe. Any remaining INSERT/UPDATE/DELETE/DROP/ALTER/CREATE targeting
// real tables will be blocked.
// Returns nil if the SP is safe, or an error describing what was found.
func ValidateSPDefinition(definition string) error {
	// Strip safe patterns: SP header + temp table ops
	cleaned := stripSafeSPPatterns(definition)

	matches := spDangerousPattern.FindAllString(cleaned, -1)
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
