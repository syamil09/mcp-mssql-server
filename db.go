package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

type Database struct {
	pool *sql.DB
}

func NewDatabase(connString string) (*Database, error) {
	pool, err := sql.Open("sqlserver", connString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	pool.SetMaxOpenConns(5)
	pool.SetMaxIdleConns(2)
	pool.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := pool.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("cannot reach SQL Server: %w", err)
	}

	return &Database{pool: pool}, nil
}

type QueryResult struct {
	Columns []string                 `json:"columns"`
	Rows    []map[string]interface{} `json:"rows"`
	Count   int                      `json:"count"`
}

func (db *Database) ExecuteQuery(ctx context.Context, query string) (*QueryResult, error) {
	rows, err := db.pool.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	return scanRows(rows)
}

// ExecuteQueryParam executes a parameterized query (e.g., WHERE col = @p1).
// Use this instead of fmt.Sprintf for any query that includes user-supplied values.
func (db *Database) ExecuteQueryParam(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	rows, err := db.pool.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	return scanRows(rows)
}

func scanRows(rows *sql.Rows) (*QueryResult, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	var result QueryResult
	result.Columns = columns

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = formatValue(values[i])
		}
		result.Rows = append(result.Rows, row)
	}

	result.Count = len(result.Rows)
	return &result, nil
}

// formatValue converts SQL driver types to JSON-friendly values.
func formatValue(v interface{}) interface{} {
	switch val := v.(type) {
	case []byte:
		return string(val)
	case time.Time:
		return val.Format(time.RFC3339)
	default:
		return val
	}
}
