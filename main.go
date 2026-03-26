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

	s := server.NewMCPServer("mcp-mssql", "2.1.0",
		server.WithInstructions(`You are connected to a SQL Server database via mcp-mssql.
You can only READ data — no writes, updates, or deletions are possible.
Always be conservative with row counts. Start with small limits before
requesting large datasets. Some tables and columns may be restricted
for security reasons — respect those boundaries.

Available tools:
- list_tables: See all queryable tables
- describe_table: Get column names and types for a table
- query_database: Execute SELECT queries`),
	)

	registerTools(s, db)

	log.Println("mcp-mssql v2.1.0 starting (stdio transport)...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
