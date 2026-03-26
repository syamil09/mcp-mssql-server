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

type Config struct {
	// Database credentials (optional — can use MSSQL_CONNECTION_STRING env var instead)
	Server            string `json:"server"`
	Port              int    `json:"port"`
	Database          string `json:"database"`
	User              string `json:"user"`
	Password          string `json:"password"`
	Encrypt           bool   `json:"encrypt"`
	ConnectionTimeout int    `json:"connection_timeout"`

	// Security config
	BlockedTables    []string `json:"blocked_tables"`
	SensitiveColumns []string `json:"sensitive_columns"`
	MaxRows          int      `json:"max_rows"`

	// Output format: "json" (default) or "toon" (token-optimized for LLMs)
	OutputFormat string `json:"output_format"`
}

var BlockedTables map[string]bool
var SensitiveColumns map[string]bool
var MaxRows int
var OutputFormat string
var LoadedConfig Config

func LoadConfig() {
	cfg := loadConfigFile()
	LoadedConfig = cfg

	BlockedTables = toMap(cfg.BlockedTables)
	SensitiveColumns = toMap(cfg.SensitiveColumns)
	MaxRows = cfg.MaxRows
	if MaxRows == 0 {
		MaxRows = 100
	}

	OutputFormat = strings.ToLower(cfg.OutputFormat)
	if OutputFormat != "toon" {
		OutputFormat = "json"
	}

	// Built-in sensitive column defaults if nothing configured
	if len(SensitiveColumns) == 0 {
		SensitiveColumns = map[string]bool{
			"password": true, "password_hash": true,
			"ssn": true, "credit_card": true,
			"salary": true, "token": true,
			"secret": true, "api_key": true,
		}
	}

	log.Printf("[CONFIG] blocked_tables=%d sensitive_columns=%d max_rows=%d",
		len(BlockedTables), len(SensitiveColumns), MaxRows)
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

// BuildConnectionString creates a go-mssqldb URL from config fields.
// Returns empty string if server is not configured (caller should fall back to env var).
func (c Config) BuildConnectionString() string {
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
