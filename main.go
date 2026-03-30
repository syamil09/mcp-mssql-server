package main

import (
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"
)

func main() {
	// Load .mcp-mssql-config.json (or env var fallback)
	LoadConfig()

	// Priority: config file credentials > MSSQL_CONNECTION_STRING env var
	connString := LoadedConfig.BuildConnectionString()
	if connString != "" {
		log.Printf("[CONNECT] Using credentials from .mcp-mssql-config.json (server=%s database=%s user=%s)",
			LoadedConfig.Server, LoadedConfig.Database, LoadedConfig.User)
	} else {
		connString = os.Getenv("MSSQL_CONNECTION_STRING")
		if connString != "" {
			log.Println("[CONNECT] Using MSSQL_CONNECTION_STRING env var")
		}
	}
	if connString == "" {
		log.Fatal("No database credentials found. Set credentials in .mcp-mssql-config.json or MSSQL_CONNECTION_STRING env var")
	}

	db, err := NewDatabase(connString)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Connected to SQL Server successfully")

	s := server.NewMCPServer("mcp-mssql", "3.0.0",
		server.WithInstructions(`You are connected to a SQL Server database via mcp-mssql.
You can only READ data — no writes, updates, or deletions are possible.
Always be conservative with row counts. Start with small limits before
requesting large datasets. Some tables and columns may be restricted
for security reasons — respect those boundaries.

Available tools:
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

Guidelines:
- For simple data retrieval, prefer query_database with SELECT
- For calling stored procedures, use exec_sp — do NOT use OPENROWSET
- For performance comparison, use benchmark_query
- You can use DECLARE with query_database for variable-based SELECT queries`),
	)

	registerTools(s, db)

	log.Println("mcp-mssql v3.0.0 starting (stdio transport)...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
