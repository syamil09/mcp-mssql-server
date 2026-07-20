package main

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ── XML structs matching .dtsx structure ──────────────────────────────────────

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

type SSISProjectManifest struct {
	ProtectionLevel string         `xml:"ProtectionLevel,attr"`
	Properties      []SSISProperty `xml:"Properties>Property"`
}

type SSISParameters struct {
	Parameters []SSISParameter `xml:"Parameter"`
}

type SSISParameter struct {
	Name       string         `xml:"Name,attr"`
	Properties []SSISProperty `xml:"Properties>Property"`
}

type SSISProperty struct {
	Name      string `xml:"Name,attr"`
	Sensitive string `xml:"Sensitive,attr"`
	Value     string `xml:",chardata"`
}

type DTSConnectionManagerFile struct {
	ObjectName          string                   `xml:"ObjectName,attr"`
	CreationName        string                   `xml:"CreationName,attr"`
	PropertyExpressions []DTSPropertyExpression  `xml:"PropertyExpression"`
	ObjectData          *DTSConnectionObjectData `xml:"ObjectData"`
}

type DTSPropertyExpression struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type DTSConnectionObjectData struct {
	ConnectionManager DTSConnectionManagerInner `xml:"ConnectionManager"`
}

type DTSConnectionManagerInner struct {
	ConnectionString string `xml:"ConnectionString,attr"`
}

// ── Output structs (clean JSON returned to MCP caller) ────────────────────────

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

type SchemaColRef struct {
	Table     string
	Column    string
	Component string
	Direction string // "input" or "output"
}

type ValidationIssue struct {
	Level     string `json:"level"` // "WARNING" or "ERROR"
	Table     string `json:"table"`
	Column    string `json:"column,omitempty"`
	Component string `json:"component,omitempty"`
	Message   string `json:"message"`
}

const (
	maskedValue        = "***MASKED***"
	maxISPACEntries    = 1000
	maxISPACEntryBytes = int64(50 * 1024 * 1024)
	maxISPACTotalBytes = uint64(200 * 1024 * 1024)
)

type ISPACBreakdownResult struct {
	ProjectName         string                       `json:"project_name"`
	FilePath            string                       `json:"file_path"`
	ProtectionLevel     string                       `json:"protection_level,omitempty"`
	TargetServerVersion string                       `json:"target_server_version,omitempty"`
	PackageCount        int                          `json:"package_count"`
	Packages            []ISPACPackageBreakdown      `json:"packages"`
	ConnectionManagers  []ISPACConnectionManagerInfo `json:"connection_managers,omitempty"`
	Parameters          []ISPACParameterInfo         `json:"parameters,omitempty"`
}

type ISPACPackageBreakdown struct {
	Package     string           `json:"package"`
	FileName    string           `json:"file_name"`
	ControlFlow []TaskInfo       `json:"control_flow"`
	DataFlows   []DataFlowDetail `json:"data_flows"`
	Tables      []TableRef       `json:"tables,omitempty"`
}

type TableRef struct {
	Table string `json:"table"`
	Usage string `json:"usage"`
}

type ISPACConnectionManagerInfo struct {
	Name                string            `json:"name"`
	FileName            string            `json:"file_name"`
	CreationName        string            `json:"creation_name,omitempty"`
	ConnectionString    string            `json:"connection_string,omitempty"`
	PropertyExpressions map[string]string `json:"property_expressions,omitempty"`
}

type ISPACParameterInfo struct {
	Name      string `json:"name"`
	DataType  string `json:"data_type,omitempty"`
	Required  string `json:"required,omitempty"`
	Sensitive string `json:"sensitive,omitempty"`
	Value     string `json:"value,omitempty"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func parseDTSX(filePath string) (*DTSPackage, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}
	return parseDTSXBytes(data)
}

func parseDTSXBytes(data []byte) (*DTSPackage, error) {
	var pkg DTSPackage
	if err := xml.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("xml parse error: %w", err)
	}
	return &pkg, nil
}

func buildISPACBreakdown(ispacPath string) (*ISPACBreakdownResult, error) {
	if strings.TrimSpace(ispacPath) == "" {
		return nil, fmt.Errorf("ispac_path is required")
	}
	if !strings.EqualFold(filepath.Ext(ispacPath), ".ispac") {
		return nil, fmt.Errorf("ispac_path must point to a .ispac file")
	}

	archive, err := zip.OpenReader(ispacPath)
	if err != nil {
		return nil, fmt.Errorf("open ispac: %w", err)
	}
	defer archive.Close()
	if len(archive.File) > maxISPACEntries {
		return nil, fmt.Errorf("ispac has too many entries: %d > %d", len(archive.File), maxISPACEntries)
	}

	result := &ISPACBreakdownResult{FilePath: ispacPath}
	var totalUncompressed uint64
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.UncompressedSize64 > uint64(maxISPACEntryBytes) {
			return nil, fmt.Errorf("entry %s is too large: %d bytes", entry.Name, entry.UncompressedSize64)
		}
		totalUncompressed += entry.UncompressedSize64
		if totalUncompressed > maxISPACTotalBytes {
			return nil, fmt.Errorf("ispac uncompressed size exceeds limit: %d bytes", totalUncompressed)
		}
		data, err := readZipEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name, err)
		}
		lowerName := strings.ToLower(entry.Name)
		switch {
		case strings.HasSuffix(lowerName, ".dtsx"):
			pkg, err := parseDTSXBytes(data)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", entry.Name, err)
			}
			result.Packages = append(result.Packages, buildISPACPackageBreakdown(entry.Name, pkg))
		case strings.HasSuffix(lowerName, ".conmgr"):
			manager, err := parseISPACConnectionManager(entry.Name, data)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", entry.Name, err)
			}
			result.ConnectionManagers = append(result.ConnectionManagers, manager)
		case strings.EqualFold(entry.Name, "Project.params"):
			params, err := parseISPACParameters(data)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", entry.Name, err)
			}
			result.Parameters = params
		case strings.EqualFold(entry.Name, "@Project.manifest"):
			if err := applyISPACManifest(result, data); err != nil {
				return nil, fmt.Errorf("parse %s: %w", entry.Name, err)
			}
		}
	}

	sort.Slice(result.Packages, func(i, j int) bool {
		return result.Packages[i].FileName < result.Packages[j].FileName
	})
	sort.Slice(result.ConnectionManagers, func(i, j int) bool {
		return result.ConnectionManagers[i].FileName < result.ConnectionManagers[j].FileName
	})
	sort.Slice(result.Parameters, func(i, j int) bool {
		return result.Parameters[i].Name < result.Parameters[j].Name
	})
	result.PackageCount = len(result.Packages)
	return result, nil
}

func readZipEntry(entry *zip.File) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, maxISPACEntryBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxISPACEntryBytes {
		return nil, fmt.Errorf("entry exceeds %d bytes", maxISPACEntryBytes)
	}
	return data, nil
}

func buildISPACPackageBreakdown(fileName string, pkg *DTSPackage) ISPACPackageBreakdown {
	breakdown := ISPACPackageBreakdown{
		Package:     pkg.ObjectName,
		FileName:    fileName,
		ControlFlow: extractTasks(pkg.Executables),
		DataFlows:   extractDataFlows(pkg.Executables),
		Tables:      extractTableRefs(pkg.Executables),
	}
	if breakdown.Package == "" {
		breakdown.Package = strings.TrimSuffix(filepath.Base(fileName), filepath.Ext(fileName))
	}
	return breakdown
}

func extractDataFlows(executables []DTSExecutable) []DataFlowDetail {
	var dataFlows []DataFlowDetail
	for _, task := range executables {
		if task.ObjectData != nil && task.ObjectData.Pipeline != nil {
			dataFlows = append(dataFlows, extractDataFlow(task.ObjectName, task.ObjectData.Pipeline))
		}
		if len(task.Children) > 0 {
			dataFlows = append(dataFlows, extractDataFlows(task.Children)...)
		}
	}
	return dataFlows
}

func extractTableRefs(executables []DTSExecutable) []TableRef {
	tableMap := map[string]string{}
	for _, task := range executables {
		collectTableRefs(task, tableMap)
	}
	refs := make([]TableRef, 0, len(tableMap))
	for table, usage := range tableMap {
		refs = append(refs, TableRef{Table: table, Usage: usage})
	}
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Table < refs[j].Table
	})
	return refs
}

func parseISPACConnectionManager(fileName string, data []byte) (ISPACConnectionManagerInfo, error) {
	var raw DTSConnectionManagerFile
	if err := xml.Unmarshal(data, &raw); err != nil {
		return ISPACConnectionManagerInfo{}, err
	}
	info := ISPACConnectionManagerInfo{
		Name:                raw.ObjectName,
		FileName:            fileName,
		CreationName:        raw.CreationName,
		PropertyExpressions: map[string]string{},
	}
	if info.Name == "" {
		info.Name = strings.TrimSuffix(filepath.Base(fileName), filepath.Ext(fileName))
	}
	if raw.ObjectData != nil && raw.ObjectData.ConnectionManager.ConnectionString != "" {
		info.ConnectionString = maskedValue
	}
	for _, expression := range raw.PropertyExpressions {
		if expression.Name != "" {
			info.PropertyExpressions[expression.Name] = maskSensitiveMetadata(expression.Name, expression.Value)
		}
	}
	if len(info.PropertyExpressions) == 0 {
		info.PropertyExpressions = nil
	}
	return info, nil
}

func parseISPACParameters(data []byte) ([]ISPACParameterInfo, error) {
	var raw SSISParameters
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	params := make([]ISPACParameterInfo, 0, len(raw.Parameters))
	for _, param := range raw.Parameters {
		props := ssisPropertyMap(param.Properties)
		value := strings.TrimSpace(props["Value"])
		info := ISPACParameterInfo{
			Name:      param.Name,
			DataType:  strings.TrimSpace(props["DataType"]),
			Required:  strings.TrimSpace(props["Required"]),
			Sensitive: strings.TrimSpace(props["Sensitive"]),
		}
		if value != "" {
			info.Value = maskedValue
		}
		params = append(params, info)
	}
	return params, nil
}

func applyISPACManifest(result *ISPACBreakdownResult, data []byte) error {
	var manifest SSISProjectManifest
	if err := xml.Unmarshal(data, &manifest); err != nil {
		return err
	}
	props := ssisPropertyMap(manifest.Properties)
	result.ProjectName = strings.TrimSpace(props["Name"])
	result.ProtectionLevel = manifest.ProtectionLevel
	result.TargetServerVersion = strings.TrimSpace(props["TargetServerVersion"])
	return nil
}

func ssisPropertyMap(properties []SSISProperty) map[string]string {
	props := map[string]string{}
	for _, prop := range properties {
		if prop.Name != "" {
			props[prop.Name] = prop.Value
		}
	}
	return props
}

func maskSensitiveMetadata(name, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if isSensitiveMetadata(name) || isSensitiveMetadata(value) {
		return maskedValue
	}
	return value
}

func isSensitiveMetadata(text string) bool {
	lower := strings.ToLower(text)
	sensitiveTerms := []string{
		"connectionstring",
		"connection string",
		"password",
		"pwd=",
		"user id=",
		"uid=",
		"data source=",
		"server=",
		"secret",
		"token",
		"credential",
	}
	for _, term := range sensitiveTerms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

// resolvePackagePath safely resolves a package name to a file path within SSISProjectPath.
// Returns an error if the resolved path escapes the configured directory.
func resolvePackagePath(packageName string) (string, error) {
	if SSISProjectPath == "" {
		return "", fmt.Errorf("project_ssis_path not configured in .mcp-mssql-config.json")
	}
	// Strip any directory components — only the base filename matters
	clean := filepath.Base(packageName)
	if !strings.HasSuffix(strings.ToLower(clean), ".dtsx") {
		clean += ".dtsx"
	}
	resolved := filepath.Join(SSISProjectPath, clean)
	// Verify the resolved path is still inside SSISProjectPath
	absResolved, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	absBase, err := filepath.Abs(SSISProjectPath)
	if err != nil {
		return "", fmt.Errorf("invalid base path: %w", err)
	}
	if !strings.HasPrefix(absResolved, absBase+string(filepath.Separator)) && absResolved != absBase {
		return "", fmt.Errorf("package name must not escape project path")
	}
	return resolved, nil
}

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

func getProperty(props []Property, name string) string {
	for _, p := range props {
		if strings.EqualFold(p.Name, name) {
			return strings.TrimSpace(p.Value)
		}
	}
	return ""
}

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

// ── Tool Handlers ─────────────────────────────────────────────────────────────

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
		output, _ := serializeAny(out)
		return mcp.NewToolResultText(output), nil
	}
}

func handleSSISBreakdownISPAC() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		ispacPath, _ := args["ispac_path"].(string)
		if ispacPath == "" {
			return mcp.NewToolResultError("ispac_path is required"), nil
		}
		result, err := buildISPACBreakdown(ispacPath)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(jsonBytes)), nil
	}
}

func handleSSISControlFlow() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		packageName, _ := args["package_name"].(string)
		if packageName == "" {
			return mcp.NewToolResultError("package_name is required"), nil
		}
		filePath, err := resolvePackagePath(packageName)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		pkg, err := parseDTSX(filePath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to parse %s: %s", packageName, err)), nil
		}
		result := ControlFlowResult{
			Package: pkg.ObjectName,
			Tasks:   extractTasks(pkg.Executables),
		}
		// Always JSON — nested tasks/children don't suit tabular TOON
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		output := string(jsonBytes)
		return mcp.NewToolResultText(output), nil
	}
}

func handleSSISDataFlow() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		packageName, _ := args["package_name"].(string)
		if packageName == "" {
			return mcp.NewToolResultError("package_name is required"), nil
		}
		filePath, err := resolvePackagePath(packageName)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
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
		// Always JSON — nested components/columns don't suit tabular TOON
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(jsonBytes)), nil
	}
}

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
		output, _ := serializeAny(result)
		return mcp.NewToolResultText(output), nil
	}
}

func handleSSISTableRefs() server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		packageName, _ := args["package_name"].(string)
		if packageName == "" {
			return mcp.NewToolResultError("package_name is required"), nil
		}
		filePath, err := resolvePackagePath(packageName)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
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
		output, _ := serializeAny(out)
		return mcp.NewToolResultText(output), nil
	}
}

func handleSSISListDeployed(cm *ConnectionManager) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		db, _, err := resolveDB(cm, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		args := req.GetArguments()
		folderName, _ := args["folder_name"].(string)
		projectName, _ := args["project_name"].(string)

		hasFilter := folderName != "" || projectName != ""

		// Lightweight columns by default; full details when filtered
		var selectCols string
		if hasFilter {
			selectCols = `f.name AS folder_name,
				pj.name AS project_name,
				pk.name AS package_name,
				pk.package_id,
				pj.deployed_by_name,
				pj.last_deployed_time`
		} else {
			selectCols = `f.name AS folder_name,
				pj.name AS project_name,
				pk.name AS package_name`
		}

		query := fmt.Sprintf(`
			SELECT %s
			FROM SSISDB.catalog.packages pk
			JOIN SSISDB.catalog.projects pj ON pk.project_id = pj.project_id
			JOIN SSISDB.catalog.folders f ON pj.folder_id = f.folder_id
			WHERE 1=1`, selectCols)

		var params []interface{}
		paramIdx := 1
		if folderName != "" {
			query += fmt.Sprintf(` AND f.name = @p%d`, paramIdx)
			params = append(params, sql.Named(fmt.Sprintf("p%d", paramIdx), folderName))
			paramIdx++
		}
		if projectName != "" {
			query += fmt.Sprintf(` AND pj.name = @p%d`, paramIdx)
			params = append(params, sql.Named(fmt.Sprintf("p%d", paramIdx), projectName))
		}
		query += ` ORDER BY f.name, pj.name, pk.name`

		result, err := db.ExecuteQueryParam(ctx, query, params...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to query SSISDB catalog. Make sure SSISDB exists and user has access: %s", err)), nil
		}

		output, err := serializeResult(result)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to serialize result: %s", err)), nil
		}
		return mcp.NewToolResultText(output), nil
	}
}

func handleSSISExecutionHistory(cm *ConnectionManager) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		db, _, err := resolveDB(cm, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		args := req.GetArguments()
		packageName, _ := args["package_name"].(string)
		if packageName == "" {
			packageName, _ = args["package_filter"].(string)
		}
		topN, _ := args["limit"].(string)
		if topN == "" {
			topN, _ = args["top"].(string)
		}
		statusFilter, _ := args["status"].(string)

		// Validate topN as integer to prevent injection
		if topN == "" {
			topN = "20"
		}
		topInt, err := strconv.Atoi(topN)
		if err != nil || topInt < 1 || topInt > 1000 {
			topInt = 20
		}

		query := fmt.Sprintf(`
			SELECT TOP %d
				e.execution_id,
				e.folder_name,
				e.project_name,
				e.package_name,
				CASE e.status
					WHEN 1 THEN 'Created'
					WHEN 2 THEN 'Running'
					WHEN 3 THEN 'Cancelled'
					WHEN 4 THEN 'Failed'
					WHEN 5 THEN 'Pending'
					WHEN 6 THEN 'Ended unexpectedly'
					WHEN 7 THEN 'Succeeded'
					WHEN 8 THEN 'Stopping'
					WHEN 9 THEN 'Completed'
				END AS status,
				e.start_time,
				e.end_time,
				DATEDIFF(SECOND, e.start_time, e.end_time) AS duration_seconds,
				e.caller_name AS executed_by
			FROM SSISDB.catalog.executions e
			WHERE 1=1`, topInt)

		var params []interface{}
		if packageName != "" {
			pkgClean := strings.TrimSuffix(packageName, ".dtsx")
			query += ` AND e.package_name LIKE '%' + @p1 + '%'`
			params = append(params, sql.Named("p1", pkgClean))
		}
		if statusFilter != "" {
			switch strings.ToLower(statusFilter) {
			case "failed":
				query += ` AND e.status = 4`
			case "succeeded":
				query += ` AND e.status = 7`
			case "running":
				query += ` AND e.status = 2`
			case "cancelled":
				query += ` AND e.status = 3`
			}
		}
		query += ` ORDER BY e.start_time DESC`

		result, err := db.ExecuteQueryParam(ctx, query, params...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to query SSISDB executions. Make sure SSISDB exists and user has access: %s", err)), nil
		}

		output, err := serializeResult(result)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to serialize result: %s", err)), nil
		}
		return mcp.NewToolResultText(output), nil
	}
}

func handleSSISSchemaValidate(cm *ConnectionManager) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		db, _, err := resolveDB(cm, req)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		args := req.GetArguments()
		packageName, _ := args["package_name"].(string)
		if packageName == "" {
			return mcp.NewToolResultError("package_name is required"), nil
		}
		filePath, err := resolvePackagePath(packageName)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		pkg, err := parseDTSX(filePath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to parse %s: %s", packageName, err)), nil
		}

		// Collect all table+column refs from the package
		var colRefs []SchemaColRef
		tableSet := map[string]string{} // table -> usage
		collectTableColRefs(pkg.Executables, &colRefs, tableSet)

		// Query DB for all referenced tables
		var issues []ValidationIssue
		var validTables []string

		// Check each table exists in DB
		dbTables := map[string]bool{}
		for table := range tableSet {
			cleanTable := cleanTableName(table)
			if cleanTable == "" {
				continue
			}
			if dbTables[strings.ToUpper(cleanTable)] {
				continue // already checked
			}

			checkQuery := `SELECT COUNT(*) AS cnt FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = @p1`
			result, err := db.ExecuteQueryParam(ctx, checkQuery, cleanTable)
			if err != nil {
				issues = append(issues, ValidationIssue{
					Level:   "WARNING",
					Table:   table,
					Message: fmt.Sprintf("Could not verify table: %s", err),
				})
				continue
			}
			cnt := 0
			if result.Count > 0 {
				if v, ok := result.Rows[0]["cnt"].(int64); ok {
					cnt = int(v)
				}
			}
			if cnt == 0 {
				issues = append(issues, ValidationIssue{
					Level:   "ERROR",
					Table:   table,
					Message: fmt.Sprintf("Table [%s] referenced in SSIS package does NOT exist in database", table),
				})
			} else {
				dbTables[strings.ToUpper(cleanTable)] = true
				validTables = append(validTables, cleanTable)
			}
		}

		// Check columns for tables that DO exist
		for _, ref := range colRefs {
			cleanTable := cleanTableName(ref.Table)
			if !dbTables[strings.ToUpper(cleanTable)] {
				continue // table already flagged as missing
			}
			if ref.Column == "" {
				continue
			}

			colQuery := `SELECT COUNT(*) AS cnt FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = @p1 AND COLUMN_NAME = @p2`
			result, err := db.ExecuteQueryParam(ctx, colQuery, cleanTable, ref.Column)
			if err != nil {
				continue
			}
			cnt := 0
			if result.Count > 0 {
				if v, ok := result.Rows[0]["cnt"].(int64); ok {
					cnt = int(v)
				}
			}
			if cnt == 0 {
				issues = append(issues, ValidationIssue{
					Level:     "WARNING",
					Table:     ref.Table,
					Column:    ref.Column,
					Component: ref.Component,
					Message:   fmt.Sprintf("Column [%s] in table [%s] referenced by SSIS component [%s] does NOT exist in database", ref.Column, ref.Table, ref.Component),
				})
			}
		}

		// Deduplicate issues
		seen := map[string]bool{}
		var deduped []ValidationIssue
		for _, iss := range issues {
			key := iss.Level + "|" + iss.Table + "|" + iss.Column + "|" + iss.Component
			if !seen[key] {
				seen[key] = true
				deduped = append(deduped, iss)
			}
		}

		errorCount := 0
		warnCount := 0
		for _, iss := range deduped {
			if iss.Level == "ERROR" {
				errorCount++
			} else {
				warnCount++
			}
		}

		status := "OK"
		if errorCount > 0 {
			status = "SCHEMA_MISMATCH"
		} else if warnCount > 0 {
			status = "WARNINGS"
		}

		out := map[string]interface{}{
			"package":      pkg.ObjectName,
			"status":       status,
			"tables_found": len(validTables),
			"tables_total": len(tableSet),
			"errors":       errorCount,
			"warnings":     warnCount,
			"issues":       deduped,
		}
		output, _ := serializeAny(out)
		return mcp.NewToolResultText(output), nil
	}
}

// collectTableColRefs recursively extracts table and column references from executables.
func collectTableColRefs(executables []DTSExecutable, colRefs *[]SchemaColRef, tableSet map[string]string) {
	for _, task := range executables {
		if task.ObjectData != nil && task.ObjectData.Pipeline != nil {
			for _, comp := range task.ObjectData.Pipeline.Components {
				table := getProperty(comp.Properties, "OpenRowset")
				cType := componentType(comp.ComponentClassID)
				if table != "" {
					if strings.Contains(cType, "Destination") {
						tableSet[table] = "Destination"
					} else {
						tableSet[table] = "Source"
					}
				}
				// Collect input columns
				for _, inp := range comp.Inputs {
					for _, col := range inp.InputColumns {
						if col.CachedName != "" && table != "" {
							*colRefs = append(*colRefs, SchemaColRef{table, col.CachedName, comp.Name, "input"})
						}
					}
				}
				// Collect output columns (for sources — these map to DB columns)
				if strings.Contains(cType, "Source") || strings.Contains(cType, "Destination") {
					for _, out := range comp.Outputs {
						if strings.Contains(strings.ToLower(out.Name), "error") {
							continue // skip error outputs
						}
						for _, col := range out.OutputColumns {
							if col.Name != "" && table != "" {
								*colRefs = append(*colRefs, SchemaColRef{table, col.Name, comp.Name, "output"})
							}
						}
					}
				}
			}
		}
		if len(task.Children) > 0 {
			collectTableColRefs(task.Children, colRefs, tableSet)
		}
	}
}

// cleanTableName strips schema prefixes and brackets: "[dbo].[MyTable]" -> "MyTable"
func cleanTableName(table string) string {
	table = strings.ReplaceAll(table, "[", "")
	table = strings.ReplaceAll(table, "]", "")
	table = strings.TrimSpace(table)
	parts := strings.Split(table, ".")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// ── Tool Registration ─────────────────────────────────────────────────────────

func registerSSISTools(s *server.MCPServer, cm *ConnectionManager) {
	connDesc := mcp.Description("Connection name from config. Uses default if omitted.")

	s.AddTool(
		mcp.NewTool("ssis_list_packages",
			mcp.WithDescription("List all SSIS .dtsx packages in the configured project_ssis_path."),
		),
		handleSSISListPackages(),
	)
	s.AddTool(
		mcp.NewTool("ssis_breakdown_ispac",
			mcp.WithDescription("Break down a local SSIS .ispac deployment archive into packages, control flow, data flow, table references, connection managers, and project parameters. Sensitive values are masked."),
			mcp.WithString("ispac_path", mcp.Required(),
				mcp.Description("Local path to the .ispac file, e.g. 'sample-data/SAM_FIRESTORE_ETL.ispac'")),
		),
		handleSSISBreakdownISPAC(),
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
	s.AddTool(
		mcp.NewTool("ssis_schema_validate",
			mcp.WithDescription("Cross-reference a SSIS package against the live database schema. Reports ERROR for tables that exist in SSIS but NOT in DB, and WARNING for columns referenced in SSIS but missing from DB. Use to detect schema drift between ETL packages and the actual database."),
			mcp.WithString("package_name", mcp.Required(),
				mcp.Description("Package name with or without .dtsx")),
			mcp.WithString("connection", connDesc),
		),
		handleSSISSchemaValidate(cm),
	)
	s.AddTool(
		mcp.NewTool("ssis_list_deployed",
			mcp.WithDescription("List SSIS packages deployed to the SSISDB catalog. Without filters: returns lightweight list (folder, project, package name only). With folder_name or project_name filter: returns full details including package_id, deployed_by, and last_deployed_time."),
			mcp.WithString("folder_name",
				mcp.Description("Filter by SSISDB folder name to get full details, e.g. 'SAM FIRESTORE'")),
			mcp.WithString("project_name",
				mcp.Description("Filter by SSISDB project name to get full details, e.g. 'SAM_FIRESTORE_ETL'")),
			mcp.WithString("connection", connDesc),
		),
		handleSSISListDeployed(cm),
	)
	s.AddTool(
		mcp.NewTool("ssis_execution_history",
			mcp.WithDescription("Get SSIS package execution history from SSISDB catalog. Shows status (Succeeded/Failed/Running), duration, start/end time, and who ran it. Supports filtering by package_name (partial match) and status."),
			mcp.WithString("package_name",
				mcp.Description("Filter by package name (partial match/LIKE), e.g. 'SAM Report_CMS'")),
			mcp.WithString("status",
				mcp.Description("Filter by status: 'failed', 'succeeded', 'running', 'cancelled'")),
			mcp.WithString("limit",
				mcp.Description("Max rows to return (default: 20)")),
			mcp.WithString("connection", connDesc),
		),
		handleSSISExecutionHistory(cm),
	)
}
