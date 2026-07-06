package main

import (
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"
)

func main() {
	// Load .mcp-mssql-config.json (or env var fallback)
	LoadConfig()

	// Support env var fallback for single-connection mode
	if defConn, ok := LoadedConfig.Connections[DefaultConnectionName]; ok && defConn.Server == "" {
		connString := os.Getenv("MSSQL_CONNECTION_STRING")
		if connString != "" {
			log.Println("[CONNECT] Using MSSQL_CONNECTION_STRING env var for default connection")
			defConn.RawConnString = connString
		}
	}

	// Verify at least one connection is configured
	hasServer := false
	for _, conn := range LoadedConfig.Connections {
		if conn.Server != "" || conn.RawConnString != "" {
			hasServer = true
			break
		}
	}
	if !hasServer {
		log.Fatal("No database credentials found. Set credentials in .mcp-mssql-config.json or MSSQL_CONNECTION_STRING env var")
	}

	cm := NewConnectionManager(LoadedConfig.Connections, DefaultConnectionName)
	defer cm.Close()

	// Eagerly connect the default connection (fail-fast if config is wrong)
	if DefaultConnectionName != "" {
		_, _, err := cm.GetConnection("")
		if err != nil {
			log.Fatalf("Failed to connect default connection '%s': %v", DefaultConnectionName, err)
		}
		log.Println("Connected to SQL Server successfully")
	}

	s := server.NewMCPServer("mcp-mssql", "4.0.0",
		server.WithInstructions(`You are connected to one or more SQL Server databases via mcp-mssql.
You can only READ data — no writes, updates, or deletions are possible.
Always be conservative with row counts. Start with small limits before
requesting large datasets. Some tables and columns may be restricted
for security reasons — respect those boundaries.

Multi-connection support:
- Use list_connections to see all available database connections
- Pass the "connection" parameter to any DB tool to target a specific connection
- If you omit "connection", the default connection is used

Available tools:
- list_connections: See all configured database connections and which is default
- list_tables: See all queryable tables
- describe_table: Get column names and types for a table
- query_database: Execute SELECT queries (supports SELECT, WITH, and DECLARE)
- exec_sp: Execute a stored procedure safely. The SP definition is inspected
  first — only read-only SPs (no INSERT/UPDATE/DELETE/DROP/ALTER) are allowed.
  Use this instead of OPENROWSET or trying to embed EXEC inside a SELECT.
  Example: exec_sp(procedure: "SAM_API_GetDataProductBySalesman", params: "@szEmployeeId = '10002088'")
- benchmark_query: Compare query performance. Pass one or two queries and get
  execution time + row count without returning the actual data. Useful for
  comparing old vs new versions of a query or SP refactoring.

SSIS ETL tools (no DB connection needed — parses .dtsx files from configured path):
- ssis_list_packages: List all .dtsx SSIS packages in the configured path
- ssis_control_flow: Extract task sequence and SQL from a single package
- ssis_data_flow: Extract components, table names, SQL queries, column mappings
- ssis_impact_check: Scan ALL packages for table/column — use before schema changes
- ssis_table_refs: List all tables a package reads from or writes to
- ssis_schema_validate: Cross-reference SSIS package vs live DB schema — reports missing tables/columns
- ssis_list_deployed: List packages deployed to SSISDB catalog on the server
- ssis_execution_history: Get execution history from SSISDB — status, duration, filter by package/status

Export tools:
- export_sql_to_json: Export query or SP results to a JSON file. Supports nested
  JSON column parsing (auto-detect or specify with json_columns param). Use
  source_column to extract JSON from a specific column as the output list.
  Files are saved to exportDatabaseSql/ folder.
  Example: export_sql_to_json(procedure: "dbo.GetProducts", params: "@categoryId = 1")
  Example: export_sql_to_json(sql: "SELECT * FROM Products", json_columns: "metadata,config")
  Example: export_sql_to_json(procedure: "dbo.GetRawData", source_column: "rawdata")
- export_sql_to_csv: Export query or SP results to CSV. Same params as export_sql_to_json
  but outputs CSV instead of JSON.
  Example: export_sql_to_csv(procedure: "dbo.GetProducts", params: "@categoryId = 1")

Compare tools:
- compare_result_sets: Compare two result sets cell-by-cell. Run two queries (possibly
  on different connections), get a detailed diff report saved as JSON. Supports row
  matching by index or key column. Use for dev-vs-prod validation or query refactoring.
  Example: compare_result_sets(sql_a: "SELECT * FROM Orders", connection_a: "dev",
    sql_b: "SELECT * FROM Orders", connection_b: "production", key_column: "OrderId")

Guidelines:
- For simple data retrieval, prefer query_database with SELECT
- For calling stored procedures, use exec_sp — do NOT use OPENROWSET
- For performance comparison, use benchmark_query
- For exporting data to JSON files, use export_sql_to_json
- For exporting data to CSV, use export_sql_to_csv
- For comparing two result sets, use compare_result_sets
- You can use DECLARE with query_database for variable-based SELECT queries`),
	)

	registerTools(s, cm)

	log.Println("mcp-mssql v4.0.0 starting (stdio transport)...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
