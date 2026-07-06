# Iteration 01: Core Parser and MCP Tools

> Part of: [SSIS ETL Tools](technical-plan.md)
> Status: planned

## Summary
Add `project_ssis_path` to config, create `ssis.go` with XML structs + parser helpers + 5 tool handlers, register tools in `tools.go`, build and deploy binary.

---

## Tasks

### Task 1: Extend Config
**Files:**
- Modify: `mcp-mssql-server/config.go`
- Modify: `sam_be_api/.mcp-mssql-config.json.example`

- [ ] **Step 1: Add SSIS field to Config struct**
```go
type Config struct {
    // ... existing fields ...

    // SSIS ETL project path for .dtsx parsing tools
    ProjectSSISPath string `json:"project_ssis_path"`
}
```

- [ ] **Step 2: Expose as package-level var in LoadConfig()**
```go
var SSISProjectPath string

func LoadConfig() {
    // ... existing code ...
    SSISProjectPath = cfg.ProjectSSISPath
    log.Printf("[CONFIG] ssis_project_path=%s", SSISProjectPath)
}
```

- [ ] **Step 3: Update .mcp-mssql-config.json.example**
```json
{
  "server": "YOUR_SERVER_IP",
  "port": 1433,
  "database": "YOUR_DATABASE",
  "user": "YOUR_USERNAME",
  "password": "YOUR_PASSWORD",
  "encrypt": false,
  "connection_timeout": 240,
  "blocked_tables": ["users","user_sessions","audit_log","api_keys","password_resets","system_config"],
  "sensitive_columns": ["password","password_hash","salary","token","secret","credit_card","pin","api_key"],
  "max_rows": 200,
  "output_format": "toon",
  "project_ssis_path": "C:\\path\\to\\SAM ETL\\SAM"
}
```

**Acceptance criteria:**
Given a config with `project_ssis_path` set,
When `LoadConfig()` runs,
Then `SSISProjectPath` is populated and logged.

---

### Task 2: Create ssis.go — XML Structs + Helpers
**Files:**
- Create: `mcp-mssql-server/ssis.go`

- [ ] **Step 1: Package declaration and imports**
```go
package main

import (
    "context"
    "encoding/json"
    "encoding/xml"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
)
```

- [ ] **Step 2: XML structs matching .dtsx structure**
```go
type DTSPackage struct {
    XMLName     xml.Name        `xml:"Executable"`
    ObjectName  string          `xml:"ObjectName,attr"`
    Executables []DTSExecutable `xml:"Executables>Executable"`
    Variables   []DTSVariable   `xml:"Variables>Variable"`
}

type DTSExecutable struct {
    RefId          string          `xml:"refId,attr"`
    ObjectName     string          `xml:"ObjectName,attr"`
    ExecutableType string          `xml:"ExecutableType,attr"`
    Description    string          `xml:"Description,attr"`
    Children       []DTSExecutable `xml:"Executables>Executable"`
    ObjectData     *DTSObjectData  `xml:"ObjectData"`
    Constraints    []DTSConstraint `xml:"PrecedenceConstraints>PrecedenceConstraint"`
}

type DTSObjectData struct {
    Pipeline *Pipeline `xml:"pipeline"`
    SQLTask  *SQLTask  `xml:"SqlTaskData"`
}

type DTSVariable struct {
    ObjectName string `xml:"ObjectName,attr"`
    Value      string `xml:"VariableValue"`
    Expression string `xml:"Expression,attr"`
}

type DTSConstraint struct {
    From  string `xml:"From,attr"`
    To    string `xml:"To,attr"`
    Value int    `xml:"Value,attr"`
}

type Pipeline struct {
    Components []Component `xml:"components>component"`
    Paths      []Path      `xml:"paths>path"`
}

type Component struct {
    RefId            string     `xml:"refId,attr"`
    Name             string     `xml:"name,attr"`
    ComponentClassID string     `xml:"componentClassID,attr"`
    Properties       []Property `xml:"properties>property"`
    Inputs           []Input    `xml:"inputs>input"`
    Outputs          []Output   `xml:"outputs>output"`
    Connections      []ConnRef  `xml:"connections>connection"`
}

type Property struct {
    Name  string `xml:"name,attr"`
    Value string `xml:",chardata"`
}

type Input struct {
    Name         string        `xml:"name,attr"`
    InputColumns []InputColumn `xml:"inputColumns>inputColumn"`
}

type Output struct {
    Name          string         `xml:"name,attr"`
    OutputColumns []OutputColumn `xml:"outputColumns>outputColumn"`
}

type InputColumn struct {
    RefId                 string `xml:"refId,attr"`
    CachedName            string `xml:"cachedName,attr"`
    LineageId             string `xml:"lineageId,attr"`
    ExternalMetadataColId string `xml:"externalMetadataColumnId,attr"`
}

type OutputColumn struct {
    RefId      string `xml:"refId,attr"`
    Name       string `xml:"name,attr"`
    LineageId  string `xml:"lineageId,attr"`
    DataType   string `xml:"dataType,attr"`
    Expression string `xml:"expression,attr"`
}

type ConnRef struct {
    Name                   string `xml:"name,attr"`
    ConnectionManagerRefId string `xml:"connectionManagerRefId,attr"`
}

type Path struct {
    StartId string `xml:"startId,attr"`
    EndId   string `xml:"endId,attr"`
}

type SQLTask struct {
    SqlStatement string `xml:"SqlStatementSource,attr"`
}
```

- [ ] **Step 3: Output structs (clean JSON returned to MCP caller)**
```go
type PackageSummary struct {
    Name     string `json:"name"`
    FilePath string `json:"file_path"`
}

type ControlFlowResult struct {
    Package string     `json:"package"`
    Tasks   []TaskInfo `json:"tasks"`
}

type TaskInfo struct {
    Name         string     `json:"name"`
    Type         string     `json:"type"`
    SQLStatement string     `json:"sql_statement,omitempty"`
    Children     []TaskInfo `json:"children,omitempty"`
}

type DataFlowResult struct {
    Package   string           `json:"package"`
    DataFlows []DataFlowDetail `json:"data_flows"`
}

type DataFlowDetail struct {
    TaskName   string            `json:"task_name"`
    Components []ComponentDetail `json:"components"`
}

type ComponentDetail struct {
    Name       string   `json:"name"`
    Type       string   `json:"type"`
    Table      string   `json:"table,omitempty"`
    SQLQuery   string   `json:"sql_query,omitempty"`
    InputCols  []string `json:"input_columns,omitempty"`
    OutputCols []string `json:"output_columns,omitempty"`
    Connection string   `json:"connection,omitempty"`
}

type ImpactResult struct {
    Table   string         `json:"table"`
    Column  string         `json:"column,omitempty"`
    Impacts []ImpactDetail `json:"impacts"`
    Total   int            `json:"total_packages_affected"`
}

type ImpactDetail struct {
    Package  string `json:"package"`
    TaskName string `json:"task_name"`
    Usage    string `json:"usage"`
    Risk     string `json:"risk"`
    Detail   string `json:"detail"`
}
```

- [ ] **Step 4: Helper — parse a single .dtsx file**
```go
func parseDTSX(filePath string) (*DTSPackage, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("read error: %w", err)
    }
    var pkg DTSPackage
    if err := xml.Unmarshal(data, &pkg); err != nil {
        return nil, fmt.Errorf("xml parse error: %w", err)
    }
    return &pkg, nil
}
```

- [ ] **Step 5: Helper — list all .dtsx files from config path**
```go
func listDTSXFiles() ([]string, error) {
    if SSISProjectPath == "" {
        return nil, fmt.Errorf("project_ssis_path not configured in .mcp-mssql-config.json")
    }
    entries, err := os.ReadDir(SSISProjectPath)
    if err != nil {
        return nil, fmt.Errorf("cannot read ssis path %s: %w", SSISProjectPath, err)
    }
    var files []string
    for _, e := range entries {
        if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".dtsx") {
            files = append(files, filepath.Join(SSISProjectPath, e.Name()))
        }
    }
    return files, nil
}
```

- [ ] **Step 6: Helper — classify componentClassID to readable string**
```go
func componentType(classID string) string {
    switch {
    case strings.Contains(classID, "OLEDBSource"):
        return "OLE DB Source"
    case strings.Contains(classID, "OLEDBDestination"):
        return "OLE DB Destination"
    case strings.Contains(classID, "DerivedColumn"):
        return "Derived Column"
    case strings.Contains(classID, "Lookup"):
        return "Lookup"
    case strings.Contains(classID, "ConditionalSplit"):
        return "Conditional Split"
    case strings.Contains(classID, "UnionAll"):
        return "Union All"
    case strings.Contains(classID, "Sort"):
        return "Sort"
    case strings.Contains(classID, "Aggregate"):
        return "Aggregate"
    case strings.Contains(classID, "RowCount"):
        return "Row Count"
    default:
        return classID
    }
}
```

- [ ] **Step 7: Helper — get property value by name**
```go
func getProperty(props []Property, name string) string {
    for _, p := range props {
        if strings.EqualFold(p.Name, name) {
            return strings.TrimSpace(p.Value)
        }
    }
    return ""
}
```

- [ ] **Step 8: Helper — simplify ExecutableType to readable string**
```go
func simplifyType(execType string) string {
    switch {
    case strings.Contains(execType, "Microsoft.Pipeline"):
        return "Data Flow Task"
    case strings.Contains(execType, "ExecuteSQLTask"):
        return "Execute SQL Task"
    case strings.Contains(execType, "ForEachLoop"):
        return "ForEach Loop"
    case strings.Contains(execType, "Sequence"):
        return "Sequence Container"
    case strings.Contains(execType, "Microsoft.Package"):
        return "Package"
    default:
        return execType
    }
}
```

- [ ] **Step 9: Helper — extract task info recursively**
```go
func extractTasks(executables []DTSExecutable) []TaskInfo {
    var tasks []TaskInfo
    for _, e := range executables {
        t := TaskInfo{
            Name: e.ObjectName,
            Type: simplifyType(e.ExecutableType),
        }
        if e.ObjectData != nil && e.ObjectData.SQLTask != nil {
            t.SQLStatement = e.ObjectData.SQLTask.SqlStatement
        }
        if len(e.Children) > 0 {
            t.Children = extractTasks(e.Children)
        }
        tasks = append(tasks, t)
    }
    return tasks
}
```

- [ ] **Step 10: Helper — extract data flow detail from pipeline**
```go
func extractDataFlow(taskName string, pipeline *Pipeline) DataFlowDetail {
    detail := DataFlowDetail{TaskName: taskName}
    for _, comp := range pipeline.Components {
        cd := ComponentDetail{
            Name:     comp.Name,
            Type:     componentType(comp.ComponentClassID),
            Table:    getProperty(comp.Properties, "OpenRowset"),
            SQLQuery: getProperty(comp.Properties, "SqlCommand"),
        }
        for _, conn := range comp.Connections {
            if conn.Name == "OleDbConnection" {
                parts := strings.Split(conn.ConnectionManagerRefId, "[")
                if len(parts) > 1 {
                    cd.Connection = strings.Trim(parts[1], "]")
                }
            }
        }
        for _, inp := range comp.Inputs {
            for _, col := range inp.InputColumns {
                if col.CachedName != "" {
                    cd.InputCols = append(cd.InputCols, col.CachedName)
                }
            }
        }
        for _, out := range comp.Outputs {
            for _, col := range out.OutputColumns {
                if col.Name != "" {
                    cd.OutputCols = append(cd.OutputCols, col.Name)
                }
            }
        }
        detail.Components = append(detail.Components, cd)
    }
    return detail
}
```

- [ ] **Step 11: Helper — collect table refs recursively**
```go
func collectTableRefs(task DTSExecutable, tableMap map[string]string) {
    if task.ObjectData != nil && task.ObjectData.Pipeline != nil {
        for _, comp := range task.ObjectData.Pipeline.Components {
            table := getProperty(comp.Properties, "OpenRowset")
            if table != "" {
                cType := componentType(comp.ComponentClassID)
                if strings.Contains(cType, "Destination") {
                    tableMap[table] = "Destination (WRITE)"
                } else {
                    tableMap[table] = "Source (READ)"
                }
            }
        }
    }
    for _, child := range task.Children {
        collectTableRefs(child, tableMap)
    }
}
```

- [ ] **Step 12: Helper — scan package for impact**
```go
func scanPackageForImpact(pkg *DTSPackage, pkgName, tableUpper, colUpper string) []ImpactDetail {
    var impacts []ImpactDetail
    for _, task := range pkg.Executables {
        impacts = append(impacts, scanTaskForImpact(task, pkgName, tableUpper, colUpper)...)
    }
    return impacts
}

func scanTaskForImpact(task DTSExecutable, pkgName, tableUpper, colUpper string) []ImpactDetail {
    var impacts []ImpactDetail

    if task.ObjectData != nil && task.ObjectData.Pipeline != nil {
        for _, comp := range task.ObjectData.Pipeline.Components {
            cType := componentType(comp.ComponentClassID)
            tableProp := strings.ToUpper(getProperty(comp.Properties, "OpenRowset"))
            sqlProp := strings.ToUpper(getProperty(comp.Properties, "SqlCommand"))

            tableMatch := strings.Contains(tableProp, tableUpper)
            sqlMatch := strings.Contains(sqlProp, tableUpper)
            if !tableMatch && !sqlMatch {
                continue
            }

            usage := "Source"
            risk := "MEDIUM"
            detail := "Table referenced in SQL query"
            if strings.Contains(cType, "Destination") {
                usage = "Destination"
                risk = "HIGH"
                detail = fmt.Sprintf("Direct OLE DB write to [%s]", tableProp)
            } else if tableMatch {
                usage = "Source"
                risk = "HIGH"
                detail = fmt.Sprintf("Direct OLE DB read from [%s]", tableProp)
            }

            if colUpper != "" {
                colFound := false
                for _, inp := range comp.Inputs {
                    for _, col := range inp.InputColumns {
                        if strings.ToUpper(col.CachedName) == colUpper {
                            colFound = true
                            detail = fmt.Sprintf("Column [%s] explicitly mapped in input", col.CachedName)
                        }
                    }
                }
                for _, out := range comp.Outputs {
                    for _, col := range out.OutputColumns {
                        if strings.ToUpper(col.Name) == colUpper {
                            colFound = true
                            detail = fmt.Sprintf("Column [%s] in output stream", col.Name)
                        }
                    }
                }
                if !colFound && strings.Contains(sqlProp, colUpper) {
                    colFound = true
                    detail = fmt.Sprintf("Column [%s] referenced in SQL query text", colUpper)
                    risk = "MEDIUM"
                }
                if !colFound {
                    continue
                }
            }

            impacts = append(impacts, ImpactDetail{
                Package:  pkgName,
                TaskName: task.ObjectName,
                Usage:    usage,
                Risk:     risk,
                Detail:   detail,
            })
        }
    }

    for _, child := range task.Children {
        impacts = append(impacts, scanTaskForImpact(child, pkgName, tableUpper, colUpper)...)
    }
    return impacts
}
```

**Acceptance criteria:**
Given a valid `.dtsx` file path,
When `parseDTSX()` is called,
Then returns a populated `DTSPackage` with executables and variables.

---

### Task 3: Add Tool Handlers to ssis.go

- [ ] **Step 1: handleSSISListPackages**
```go
func handleSSISListPackages() server.ToolHandlerFunc {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        files, err := listDTSXFiles()
        if err != nil {
            return mcp.NewToolResultError(err.Error()), nil
        }
        var packages []PackageSummary
        for _, f := range files {
            packages = append(packages, PackageSummary{
                Name:     strings.TrimSuffix(filepath.Base(f), ".dtsx"),
                FilePath: f,
            })
        }
        out := map[string]interface{}{
            "packages": packages,
            "count":    len(packages),
            "path":     SSISProjectPath,
        }
        jsonBytes, _ := json.MarshalIndent(out, "", "  ")
        return mcp.NewToolResultText(string(jsonBytes)), nil
    }
}
```

- [ ] **Step 2: handleSSISControlFlow**
```go
func handleSSISControlFlow() server.ToolHandlerFunc {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        args := req.GetArguments()
        packageName, _ := args["package_name"].(string)
        if packageName == "" {
            return mcp.NewToolResultError("package_name is required"), nil
        }
        filePath := filepath.Join(SSISProjectPath, packageName)
        if !strings.HasSuffix(strings.ToLower(filePath), ".dtsx") {
            filePath += ".dtsx"
        }
        pkg, err := parseDTSX(filePath)
        if err != nil {
            return mcp.NewToolResultError(fmt.Sprintf("failed to parse %s: %s", packageName, err)), nil
        }
        result := ControlFlowResult{
            Package: pkg.ObjectName,
            Tasks:   extractTasks(pkg.Executables),
        }
        jsonBytes, _ := json.MarshalIndent(result, "", "  ")
        return mcp.NewToolResultText(string(jsonBytes)), nil
    }
}
```

- [ ] **Step 3: handleSSISDataFlow**
```go
func handleSSISDataFlow() server.ToolHandlerFunc {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        args := req.GetArguments()
        packageName, _ := args["package_name"].(string)
        if packageName == "" {
            return mcp.NewToolResultError("package_name is required"), nil
        }
        filePath := filepath.Join(SSISProjectPath, packageName)
        if !strings.HasSuffix(strings.ToLower(filePath), ".dtsx") {
            filePath += ".dtsx"
        }
        pkg, err := parseDTSX(filePath)
        if err != nil {
            return mcp.NewToolResultError(fmt.Sprintf("failed to parse %s: %s", packageName, err)), nil
        }
        result := DataFlowResult{Package: pkg.ObjectName}
        for _, task := range pkg.Executables {
            if task.ObjectData != nil && task.ObjectData.Pipeline != nil {
                df := extractDataFlow(task.ObjectName, task.ObjectData.Pipeline)
                result.DataFlows = append(result.DataFlows, df)
            }
            for _, child := range task.Children {
                if child.ObjectData != nil && child.ObjectData.Pipeline != nil {
                    df := extractDataFlow(child.ObjectName, child.ObjectData.Pipeline)
                    result.DataFlows = append(result.DataFlows, df)
                }
            }
        }
        jsonBytes, _ := json.MarshalIndent(result, "", "  ")
        return mcp.NewToolResultText(string(jsonBytes)), nil
    }
}
```

- [ ] **Step 4: handleSSISImpactCheck**
```go
func handleSSISImpactCheck() server.ToolHandlerFunc {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        args := req.GetArguments()
        tableName, _ := args["table_name"].(string)
        columnName, _ := args["column_name"].(string)
        if tableName == "" {
            return mcp.NewToolResultError("table_name is required"), nil
        }
        files, err := listDTSXFiles()
        if err != nil {
            return mcp.NewToolResultError(err.Error()), nil
        }
        result := ImpactResult{Table: tableName, Column: columnName}
        tableUpper := strings.ToUpper(tableName)
        colUpper := strings.ToUpper(columnName)
        for _, f := range files {
            pkg, err := parseDTSX(f)
            if err != nil {
                continue
            }
            pkgName := strings.TrimSuffix(filepath.Base(f), ".dtsx")
            impacts := scanPackageForImpact(pkg, pkgName, tableUpper, colUpper)
            result.Impacts = append(result.Impacts, impacts...)
        }
        result.Total = len(result.Impacts)
        jsonBytes, _ := json.MarshalIndent(result, "", "  ")
        return mcp.NewToolResultText(string(jsonBytes)), nil
    }
}
```

- [ ] **Step 5: handleSSISTableRefs**
```go
func handleSSISTableRefs() server.ToolHandlerFunc {
    return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        args := req.GetArguments()
        packageName, _ := args["package_name"].(string)
        if packageName == "" {
            return mcp.NewToolResultError("package_name is required"), nil
        }
        filePath := filepath.Join(SSISProjectPath, packageName)
        if !strings.HasSuffix(strings.ToLower(filePath), ".dtsx") {
            filePath += ".dtsx"
        }
        pkg, err := parseDTSX(filePath)
        if err != nil {
            return mcp.NewToolResultError(fmt.Sprintf("failed to parse %s: %s", packageName, err)), nil
        }
        tableMap := map[string]string{}
        for _, task := range pkg.Executables {
            collectTableRefs(task, tableMap)
        }
        type TableRef struct {
            Table string `json:"table"`
            Usage string `json:"usage"`
        }
        var refs []TableRef
        for t, u := range tableMap {
            refs = append(refs, TableRef{Table: t, Usage: u})
        }
        out := map[string]interface{}{
            "package": pkg.ObjectName,
            "tables":  refs,
            "count":   len(refs),
        }
        jsonBytes, _ := json.MarshalIndent(out, "", "  ")
        return mcp.NewToolResultText(string(jsonBytes)), nil
    }
}
```

- [ ] **Step 6: registerSSISTools function**
```go
func registerSSISTools(s *server.MCPServer) {
    s.AddTool(
        mcp.NewTool("ssis_list_packages",
            mcp.WithDescription("List all SSIS .dtsx packages in the configured project_ssis_path."),
        ),
        handleSSISListPackages(),
    )
    s.AddTool(
        mcp.NewTool("ssis_control_flow",
            mcp.WithDescription("Extract control flow from a SSIS package: task names, types, sequence, and any embedded SQL statements."),
            mcp.WithString("package_name", mcp.Required(),
                mcp.Description("Package name with or without .dtsx, e.g. 'BosNet Daily'")),
        ),
        handleSSISControlFlow(),
    )
    s.AddTool(
        mcp.NewTool("ssis_data_flow",
            mcp.WithDescription("Extract data flow details from a SSIS package: components, table names, SQL queries, and column mappings for each Data Flow Task."),
            mcp.WithString("package_name", mcp.Required(),
                mcp.Description("Package name with or without .dtsx")),
        ),
        handleSSISDataFlow(),
    )
    s.AddTool(
        mcp.NewTool("ssis_impact_check",
            mcp.WithDescription("Scan ALL SSIS packages for references to a table or column. Use before any schema change to find what ETL breaks. Optionally narrow by column name."),
            mcp.WithString("table_name", mcp.Required(),
                mcp.Description("Table name to search, e.g. 'BOS_SD_FTO'")),
            mcp.WithString("column_name",
                mcp.Description("Optional column name, e.g. 'szSalesId'")),
        ),
        handleSSISImpactCheck(),
    )
    s.AddTool(
        mcp.NewTool("ssis_table_refs",
            mcp.WithDescription("List all database tables a single SSIS package reads from or writes to."),
            mcp.WithString("package_name", mcp.Required(),
                mcp.Description("Package name with or without .dtsx")),
        ),
        handleSSISTableRefs(),
    )
}
```

**Acceptance criteria:**
Given `project_ssis_path` is configured,
When `ssis_list_packages` is called,
Then returns list of ~50 packages from the SAM ETL folder.

---

### Task 4: Register in tools.go
**File:** Modify `mcp-mssql-server/tools.go`

- [ ] **Step 1: Call registerSSISTools at end of registerTools**
```go
func registerTools(s *server.MCPServer, db *Database) {
    // ... all existing tool registrations unchanged ...

    registerSSISTools(s)
}
```

**File:** Modify `mcp-mssql-server/main.go`

- [ ] **Step 2: Add SSIS tools to server instructions string**

In the `WithInstructions(...)` block, append:
```
- ssis_list_packages: List all .dtsx SSIS packages in the configured path
- ssis_control_flow: Extract task sequence and SQL from a single package
- ssis_data_flow: Extract components, table names, SQL queries, column mappings
- ssis_impact_check: Scan ALL packages for table/column — use before schema changes
- ssis_table_refs: List all tables a package reads from or writes to
```

**Acceptance criteria:**
Given the updated tools.go,
When the server starts,
Then all 5 SSIS tools appear alongside existing DB tools.

---

### Task 5: Build and Deploy
**Files:** Binary in `sam_be_api/`

- [ ] **Step 1: Build binary**
```bash
cd "C:\Users\Leonovo\Documents\Bentang Project\mcp-mssql-server"
go build -o mcp-mssql.exe .
```

- [ ] **Step 2: Copy binary to project**
```bash
cp mcp-mssql.exe "C:\Users\Leonovo\Documents\Bentang Project\sam_be_api\mcp-mssql.exe"
```

- [ ] **Step 3: Update .mcp-mssql-config.json with SSIS path**
```json
{
  "project_ssis_path": "C:\\Users\\Leonovo\\Documents\\Bentang Project\\SAM ETL\\SAM"
}
```

- [ ] **Step 4: Restart Claude Code to reload MCP**
```
Close and reopen Claude Code session
→ Call ssis_list_packages → should return ~50 packages
→ Call ssis_control_flow with "BosNet Daily" → should return task list
→ Call ssis_impact_check with "BOS_SD_FTO" → should return 40 packages
```

**Acceptance criteria:**
Given the binary is deployed and config updated,
When Claude Code restarts,
Then all 5 ssis_* tools are available and ssis_impact_check("BOS_SD_FTO") returns 40 affected packages.

---

## Self-Review

**Known limitation:**
SQL queries stored as SSIS **variable expressions** (`DTS:Variables`) are not scanned by `ssis_impact_check`. Example: `SAM Report_CMS.dtsx` stores queries in `Query_SAM_Stg_ReportDisplayCompliance` variable. This means `ssis_impact_check` may under-report for packages that use variable-based dynamic SQL. Iteration 02 can add variable scanning if needed.

**All SAM constraints satisfied:**
- No inline SQL, no DB writes, no Task.Run, no ORM — purely file I/O
- Additive only — zero changes to existing DB tool behavior
- No DLL rebuild needed — Go project
