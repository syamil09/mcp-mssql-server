package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ConnectionConfig holds per-connection database credentials and security settings.
type ConnectionConfig struct {
	Server            string   `json:"server"`
	Port              int      `json:"port"`
	Database          string   `json:"database"`
	User              string   `json:"user"`
	Password          string   `json:"password"`
	Encrypt           bool     `json:"encrypt"`
	ConnectionTimeout int      `json:"connection_timeout"`
	BlockedTables     []string `json:"blocked_tables"`
	SensitiveColumns  []string `json:"sensitive_columns"`
	MaxRows           int      `json:"max_rows"`
	IsDefault         bool     `json:"default"`

	// Resolved at load time (not serialized)
	BlockedTablesMap    map[string]bool `json:"-"`
	SensitiveColumnsMap map[string]bool `json:"-"`
	MaxRowsResolved     int             `json:"-"`
	RawConnString       string          `json:"-"` // pre-built connection string (e.g. from env var)
}

// BuildConnectionString creates a go-mssqldb URL from connection config fields.
// Returns empty string if server is not configured.
func (c *ConnectionConfig) BuildConnectionString() string {
	if c.RawConnString != "" {
		return c.RawConnString
	}
	if c.Server == "" {
		return ""
	}

	port := c.Port
	if port == 0 {
		port = 1433
	}

	timeout := c.ConnectionTimeout
	if timeout == 0 {
		timeout = 30
	}

	encrypt := "disable"
	if c.Encrypt {
		encrypt = "true"
	}

	connURL := fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s&encrypt=%s&connection+timeout=%d",
		url.PathEscape(c.User),
		url.PathEscape(c.Password),
		c.Server,
		port,
		url.QueryEscape(c.Database),
		encrypt,
		timeout,
	)

	return connURL
}

// resolveDefaults populates the resolved maps and applies defaults.
func (c *ConnectionConfig) resolveDefaults() {
	c.BlockedTablesMap = toMap(c.BlockedTables)
	c.SensitiveColumnsMap = toMap(c.SensitiveColumns)
	c.MaxRowsResolved = c.MaxRows
	if c.MaxRowsResolved == 0 {
		c.MaxRowsResolved = 100
	}

	// Built-in sensitive column defaults if nothing configured
	if len(c.SensitiveColumnsMap) == 0 {
		c.SensitiveColumnsMap = map[string]bool{
			"password": true, "password_hash": true,
			"ssn": true, "credit_card": true,
			"salary": true, "token": true,
			"secret": true, "api_key": true,
		}
	}
}

type Config struct {
	// Multi-connection support: named connections
	Connections map[string]*ConnectionConfig `json:"connections"`

	// Legacy flat fields (backward compat — used when "connections" is absent)
	Server            string   `json:"server"`
	Port              int      `json:"port"`
	Database          string   `json:"database"`
	User              string   `json:"user"`
	Password          string   `json:"password"`
	Encrypt           bool     `json:"encrypt"`
	ConnectionTimeout int      `json:"connection_timeout"`
	BlockedTables     []string `json:"blocked_tables"`
	SensitiveColumns  []string `json:"sensitive_columns"`
	MaxRows           int      `json:"max_rows"`

	// Global settings (not per-connection)
	OutputFormat    string `json:"output_format"`
	ExportMaxRows   int    `json:"export_max_rows"`
	ExportDir       string `json:"export_dir"`
	ProjectSSISPath string `json:"project_ssis_path"`
}

// Global settings (not per-connection)
var OutputFormat string
var SSISProjectPath string
var LoadedConfig Config
var DefaultConnectionName string

// Legacy globals — populated from the default connection for backward compat
var BlockedTables map[string]bool
var SensitiveColumns map[string]bool
var MaxRows int

func LoadConfig() {
	cfg := loadConfigFile()
	LoadedConfig = cfg

	// If "connections" map is empty but legacy flat fields are present, synthesize
	if len(cfg.Connections) == 0 {
		conn := &ConnectionConfig{
			Server:            cfg.Server,
			Port:              cfg.Port,
			Database:          cfg.Database,
			User:              cfg.User,
			Password:          cfg.Password,
			Encrypt:           cfg.Encrypt,
			ConnectionTimeout: cfg.ConnectionTimeout,
			BlockedTables:     cfg.BlockedTables,
			SensitiveColumns:  cfg.SensitiveColumns,
			MaxRows:           cfg.MaxRows,
			IsDefault:         true,
		}
		cfg.Connections = map[string]*ConnectionConfig{"default": conn}
		LoadedConfig.Connections = cfg.Connections
	}

	// Determine default connection name
	DefaultConnectionName = ""
	for name, conn := range cfg.Connections {
		conn.resolveDefaults()
		if conn.IsDefault {
			DefaultConnectionName = name
		}
	}
	// If no explicit default and only one connection, use it
	if DefaultConnectionName == "" {
		if len(cfg.Connections) == 1 {
			for name := range cfg.Connections {
				DefaultConnectionName = name
			}
		}
	}

	// Populate legacy globals from default connection
	if defConn, ok := cfg.Connections[DefaultConnectionName]; ok {
		BlockedTables = defConn.BlockedTablesMap
		SensitiveColumns = defConn.SensitiveColumnsMap
		MaxRows = defConn.MaxRowsResolved
	} else {
		BlockedTables = make(map[string]bool)
		SensitiveColumns = make(map[string]bool)
		MaxRows = 100
	}

	OutputFormat = strings.ToLower(cfg.OutputFormat)
	if OutputFormat != "toon" {
		OutputFormat = "json"
	}

	SSISProjectPath = cfg.ProjectSSISPath

	if cfg.ExportMaxRows > 0 {
		ExportMaxRows = cfg.ExportMaxRows
	}
	if cfg.ExportDir != "" {
		ExportDirOverride = cfg.ExportDir
	}

	log.Printf("[CONFIG] connections=%d default=%q output_format=%s export_max_rows=%d ssis_project_path=%s",
		len(cfg.Connections), DefaultConnectionName, OutputFormat, ExportMaxRows, SSISProjectPath)
	for name, conn := range cfg.Connections {
		marker := ""
		if name == DefaultConnectionName {
			marker = " (default)"
		}
		log.Printf("[CONFIG]   connection %q%s: server=%s database=%s blocked_tables=%d sensitive_columns=%d max_rows=%d",
			name, marker, conn.Server, conn.Database, len(conn.BlockedTablesMap), len(conn.SensitiveColumnsMap), conn.MaxRowsResolved)
	}
}

func loadConfigFile() Config {
	var cfg Config

	// Priority 1: look next to the executable
	var configPath string
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		candidate := filepath.Join(exeDir, ".mcp-mssql-config.json")
		if _, err := os.Stat(candidate); err == nil {
			configPath = candidate
		}
	}

	// Priority 2: current working directory
	if configPath == "" {
		candidate := ".mcp-mssql-config.json"
		if _, err := os.Stat(candidate); err == nil {
			configPath = candidate
		}
	}

	// Priority 3: explicit path via env var
	if configPath == "" {
		configPath = os.Getenv("MSSQL_CONFIG_FILE")
	}

	// Priority 4: no config found
	if configPath == "" {
		configPath = ".mcp-mssql-config.json" // will fail, triggers env var fallback
	}

	cwd, _ := os.Getwd()
	log.Printf("[CONFIG] cwd=%s configPath=%s", cwd, configPath)

	data, err := os.ReadFile(configPath)
	if err != nil {
		// Config file is optional — fall back to env vars
		log.Printf("[CONFIG] no config file at %s, falling back to env vars", configPath)
		cfg.BlockedTables = splitCSV(os.Getenv("MSSQL_BLOCKED_TABLES"))
		cfg.SensitiveColumns = splitCSV(os.Getenv("MSSQL_SENSITIVE_COLUMNS"))
		return cfg
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("[CONFIG] invalid JSON in %s: %v", configPath, err)
	}

	log.Printf("[CONFIG] loaded from %s", configPath)
	return cfg
}

func toMap(items []string) map[string]bool {
	result := make(map[string]bool)
	for _, item := range items {
		key := strings.ToLower(strings.TrimSpace(item))
		if key != "" {
			result[key] = true
		}
	}
	return result
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			result = append(result, t)
		}
	}
	return result
}
