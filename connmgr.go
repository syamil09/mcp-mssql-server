package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
)

// ConnectionManager manages multiple named database connections with lazy initialization.
type ConnectionManager struct {
	mu          sync.RWMutex
	configs     map[string]*ConnectionConfig
	pools       map[string]*Database
	defaultName string
}

// NewConnectionManager creates a manager from the loaded connection configs.
// Pools are NOT created here — they are lazily initialized on first use.
func NewConnectionManager(configs map[string]*ConnectionConfig, defaultName string) *ConnectionManager {
	return &ConnectionManager{
		configs:     configs,
		pools:       make(map[string]*Database),
		defaultName: defaultName,
	}
}

// GetConnection returns the Database pool and ConnectionConfig for the given name.
// If name is empty, uses the default connection. Creates the pool on first use.
func (cm *ConnectionManager) GetConnection(name string) (*Database, *ConnectionConfig, error) {
	if name == "" {
		name = cm.defaultName
	}
	if name == "" {
		return nil, nil, fmt.Errorf("no default connection configured. Specify 'connection' parameter. Available: %s",
			strings.Join(cm.ListConnections(), ", "))
	}

	cfg, ok := cm.configs[name]
	if !ok {
		return nil, nil, fmt.Errorf("unknown connection '%s'. Available connections: %s",
			name, strings.Join(cm.ListConnections(), ", "))
	}

	// Fast path: pool already exists
	cm.mu.RLock()
	db, exists := cm.pools[name]
	cm.mu.RUnlock()
	if exists {
		return db, cfg, nil
	}

	// Slow path: create pool (double-check locking)
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Re-check after acquiring write lock
	if db, exists = cm.pools[name]; exists {
		return db, cfg, nil
	}

	connString := cfg.BuildConnectionString()
	if connString == "" {
		return nil, nil, fmt.Errorf("connection '%s' has no server configured", name)
	}

	log.Printf("[CONNECT] Initializing connection '%s' (server=%s database=%s user=%s)",
		name, cfg.Server, cfg.Database, cfg.User)

	db, err := NewDatabase(connString)
	if err != nil {
		return nil, nil, fmt.Errorf("connection '%s' failed: %w", name, err)
	}

	cm.pools[name] = db
	log.Printf("[CONNECT] Connection '%s' established successfully", name)
	return db, cfg, nil
}

// ListConnections returns sorted connection names.
func (cm *ConnectionManager) ListConnections() []string {
	names := make([]string, 0, len(cm.configs))
	for name := range cm.configs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// DefaultName returns the name of the default connection.
func (cm *ConnectionManager) DefaultName() string {
	return cm.defaultName
}

// Configs returns the connection configs map.
func (cm *ConnectionManager) Configs() map[string]*ConnectionConfig {
	return cm.configs
}

// Close closes all initialized connection pools.
func (cm *ConnectionManager) Close() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for name, db := range cm.pools {
		log.Printf("[CONNECT] Closing connection '%s'", name)
		db.Close()
	}
}

// resolveDB extracts the "connection" parameter from a tool request and returns
// the corresponding Database and ConnectionConfig. Helper for tool handlers.
func resolveDB(cm *ConnectionManager, req mcp.CallToolRequest) (*Database, *ConnectionConfig, error) {
	args := req.GetArguments()
	connName, _ := args["connection"].(string)
	return cm.GetConnection(strings.TrimSpace(connName))
}
