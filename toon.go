package main

import (
	"fmt"
	"strings"
)

// ToTOON converts a QueryResult to TOON (Token-Oriented Object Notation) format.
// TOON uses tabular encoding for uniform arrays of objects, reducing token usage by 30-60%.
func (r *QueryResult) ToTOON() string {
	if r == nil || len(r.Columns) == 0 {
		return "count: 0\ncolumns[0]:"
	}

	var sb strings.Builder

	// count
	sb.WriteString(fmt.Sprintf("count: %d", r.Count))

	// columns as inline array
	sb.WriteString(fmt.Sprintf("\ncolumns[%d]: %s", len(r.Columns), strings.Join(r.Columns, ",")))

	// rows as tabular array
	if len(r.Rows) == 0 {
		sb.WriteString(fmt.Sprintf("\nrows[0]{%s}:", strings.Join(r.Columns, ",")))
	} else {
		sb.WriteString(fmt.Sprintf("\nrows[%d]{%s}:", len(r.Rows), strings.Join(r.Columns, ",")))
		for _, row := range r.Rows {
			sb.WriteString("\n  ")
			for i, col := range r.Columns {
				if i > 0 {
					sb.WriteString(",")
				}
				sb.WriteString(toonValue(row[col]))
			}
		}
	}

	return sb.String()
}

// toonValue converts a single value to its TOON string representation.
func toonValue(v interface{}) string {
	if v == nil {
		return "null"
	}

	switch val := v.(type) {
	case bool:
		if val {
			return "true"
		}
		return "false"
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", val)
	case float32:
		return formatFloat(float64(val))
	case float64:
		return formatFloat(val)
	case string:
		return toonString(val)
	default:
		return toonString(fmt.Sprintf("%v", val))
	}
}

// formatFloat renders a float in canonical TOON form:
// no trailing zeros, no exponent notation, integer if whole number.
func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	s := fmt.Sprintf("%g", f)
	// %g may use exponent for large numbers — fall back to %f
	if strings.ContainsAny(s, "eE") {
		s = strings.TrimRight(fmt.Sprintf("%f", f), "0")
		s = strings.TrimRight(s, ".")
	}
	return s
}

// toonString returns the TOON representation of a string.
// Unquoted unless it needs quoting (contains delimiters, looks like a keyword/number, etc).
func toonString(s string) string {
	if s == "" {
		return `""`
	}

	// Must quote if it matches a TOON keyword
	if s == "true" || s == "false" || s == "null" {
		return `"` + s + `"`
	}

	needsQuote := false

	// Check for characters that require quoting
	for _, r := range s {
		switch r {
		case ',', ':', '"', '\\', '[', ']', '{', '}', '\n', '\r', '\t':
			needsQuote = true
		}
		if needsQuote {
			break
		}
	}

	// Leading/trailing whitespace
	if !needsQuote && (s[0] == ' ' || s[len(s)-1] == ' ') {
		needsQuote = true
	}

	// Looks numeric
	if !needsQuote && looksNumeric(s) {
		needsQuote = true
	}

	if !needsQuote {
		return s
	}

	// Escape special characters
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, "\n", `\n`)
	escaped = strings.ReplaceAll(escaped, "\r", `\r`)
	escaped = strings.ReplaceAll(escaped, "\t", `\t`)

	return `"` + escaped + `"`
}

// looksNumeric checks if a string would be parsed as a number by TOON.
func looksNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	start := 0
	if s[0] == '-' {
		start = 1
		if len(s) == 1 {
			return false
		}
	}
	// Leading zero followed by digits
	if start < len(s) && s[start] == '0' && start+1 < len(s) && s[start+1] >= '0' && s[start+1] <= '9' {
		return true
	}
	hasDigit := false
	hasDot := false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '.' && !hasDot:
			hasDot = true
		case c == 'e' || c == 'E':
			return hasDigit
		default:
			return false
		}
	}
	return hasDigit
}
