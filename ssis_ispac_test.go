package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestBuildISPACBreakdownParsesPackagesAndMasksSensitiveValues(t *testing.T) {
	ispacPath := createTestISPAC(t)

	breakdown, err := buildISPACBreakdown(ispacPath)
	if err != nil {
		t.Fatalf("buildISPACBreakdown() error = %v", err)
	}

	if breakdown.ProjectName != "TestProject" {
		t.Fatalf("ProjectName = %q, want TestProject", breakdown.ProjectName)
	}
	if breakdown.PackageCount != 3 {
		t.Fatalf("PackageCount = %d, want 3", breakdown.PackageCount)
	}
	if len(breakdown.Packages) != 3 {
		t.Fatalf("len(Packages) = %d, want 3", len(breakdown.Packages))
	}

	packageNames := map[string]bool{}
	for _, pkg := range breakdown.Packages {
		packageNames[pkg.Package] = true
		if len(pkg.ControlFlow) == 0 {
			t.Fatalf("package %s has no control flow tasks", pkg.Package)
		}
		if len(pkg.DataFlows) != 1 {
			t.Fatalf("package %s data flow count = %d, want 1", pkg.Package, len(pkg.DataFlows))
		}
	}
	for _, want := range []string{"PackageOne", "PackageTwo", "PackageThree"} {
		if !packageNames[want] {
			t.Fatalf("missing package %s in ISPAC breakdown", want)
		}
	}

	if len(breakdown.ConnectionManagers) != 1 {
		t.Fatalf("len(ConnectionManagers) = %d, want 1", len(breakdown.ConnectionManagers))
	}
	if breakdown.ConnectionManagers[0].Name != "SAM_Prod" {
		t.Fatalf("connection manager name = %q, want SAM_Prod", breakdown.ConnectionManagers[0].Name)
	}
	if breakdown.ConnectionManagers[0].ConnectionString != maskedValue {
		t.Fatalf("connection string was not masked")
	}

	if len(breakdown.Parameters) != 1 {
		t.Fatalf("len(Parameters) = %d, want 1", len(breakdown.Parameters))
	}
	if breakdown.Parameters[0].Name != "DBSamConnectionString" {
		t.Fatalf("parameter name = %q, want DBSamConnectionString", breakdown.Parameters[0].Name)
	}
	if breakdown.Parameters[0].Value != maskedValue {
		t.Fatalf("parameter value was not masked")
	}

	rawJSON, err := json.Marshal(breakdown)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	text := string(rawJSON)
	for _, forbidden := range []string{"Password=", "User ID=", "Data Source="} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("breakdown leaked sensitive value containing %q", forbidden)
		}
	}
}

func TestHandleSSISBreakdownISPACReturnsJSON(t *testing.T) {
	ispacPath := createTestISPAC(t)

	handler := handleSSISBreakdownISPAC()
	result, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: map[string]any{"ispac_path": ispacPath},
		},
	})
	if err != nil {
		t.Fatalf("handler error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handler returned tool error: %#v", result.Content)
	}
	if len(result.Content) != 1 {
		t.Fatalf("content count = %d, want 1", len(result.Content))
	}

	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want mcp.TextContent", result.Content[0])
	}
	var breakdown ISPACBreakdownResult
	if err := json.Unmarshal([]byte(text.Text), &breakdown); err != nil {
		t.Fatalf("handler returned invalid JSON: %v", err)
	}
	if breakdown.PackageCount != 3 {
		t.Fatalf("PackageCount = %d, want 3", breakdown.PackageCount)
	}
}

func TestBuildISPACBreakdownParsesSampleWhenAvailable(t *testing.T) {
	const samplePath = "sample-data/SAM_FIRESTORE_ETL.ispac"
	if _, err := os.Stat(samplePath); os.IsNotExist(err) {
		t.Skip("sample ISPAC not available")
	} else if err != nil {
		t.Fatalf("os.Stat(%q) error = %v", samplePath, err)
	}

	breakdown, err := buildISPACBreakdown(samplePath)
	if err != nil {
		t.Fatalf("buildISPACBreakdown(sample) error = %v", err)
	}
	if breakdown.ProjectName != "SAM_FIRESTORE_ETL" {
		t.Fatalf("ProjectName = %q, want SAM_FIRESTORE_ETL", breakdown.ProjectName)
	}
	if breakdown.PackageCount != 3 {
		t.Fatalf("PackageCount = %d, want 3", breakdown.PackageCount)
	}
}

func TestBuildISPACBreakdownRejectsTooManyEntries(t *testing.T) {
	ispacPath := filepath.Join(t.TempDir(), "too-many.ispac")
	file, err := os.Create(ispacPath)
	if err != nil {
		t.Fatalf("os.Create() error = %v", err)
	}
	defer file.Close()

	archive := zip.NewWriter(file)
	for i := 0; i < maxISPACEntries+1; i++ {
		writer, err := archive.Create("entry" + strconv.Itoa(i) + ".txt")
		if err != nil {
			t.Fatalf("archive.Create() error = %v", err)
		}
		if _, err := writer.Write([]byte("x")); err != nil {
			t.Fatalf("writer.Write() error = %v", err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("archive.Close() error = %v", err)
	}

	_, err = buildISPACBreakdown(ispacPath)
	if err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("error = %v, want too many entries", err)
	}
}

func createTestISPAC(t *testing.T) string {
	t.Helper()

	ispacPath := filepath.Join(t.TempDir(), "test.ispac")
	file, err := os.Create(ispacPath)
	if err != nil {
		t.Fatalf("os.Create() error = %v", err)
	}
	defer file.Close()

	archive := zip.NewWriter(file)
	entries := map[string]string{
		"PackageOne.dtsx":   testDTSX("PackageOne"),
		"PackageTwo.dtsx":   testDTSX("PackageTwo"),
		"PackageThree.dtsx": testDTSX("PackageThree"),
		"Test.conmgr": `<?xml version="1.0"?>
<DTS:ConnectionManager xmlns:DTS="www.microsoft.com/SqlServer/Dts" DTS:ObjectName="SAM_Prod" DTS:CreationName="OLEDB">
  <DTS:PropertyExpression DTS:Name="ConnectionString">Data Source=test;User ID=tester;Password=secret;Initial Catalog=db;</DTS:PropertyExpression>
  <DTS:ObjectData>
    <DTS:ConnectionManager DTS:ConnectionString="Data Source=test;User ID=tester;Password=secret;Initial Catalog=db;" />
  </DTS:ObjectData>
</DTS:ConnectionManager>`,
		"Project.params": `<?xml version="1.0"?>
<SSIS:Parameters xmlns:SSIS="www.microsoft.com/SqlServer/SSIS">
  <SSIS:Parameter SSIS:Name="DBSamConnectionString">
    <SSIS:Properties>
      <SSIS:Property SSIS:Name="Required">0</SSIS:Property>
      <SSIS:Property SSIS:Name="Sensitive">0</SSIS:Property>
      <SSIS:Property SSIS:Name="Value">Data Source=test;User ID=tester;Password=secret;Initial Catalog=db;</SSIS:Property>
      <SSIS:Property SSIS:Name="DataType">18</SSIS:Property>
    </SSIS:Properties>
  </SSIS:Parameter>
</SSIS:Parameters>`,
		"@Project.manifest": `<SSIS:Project SSIS:ProtectionLevel="EncryptSensitiveWithUserKey" xmlns:SSIS="www.microsoft.com/SqlServer/SSIS">
  <SSIS:Properties>
    <SSIS:Property SSIS:Name="Name">TestProject</SSIS:Property>
    <SSIS:Property SSIS:Name="TargetServerVersion">150</SSIS:Property>
  </SSIS:Properties>
</SSIS:Project>`,
		"[Content_Types].xml": `<?xml version="1.0"?><Types />`,
	}

	for name, content := range entries {
		writer, err := archive.Create(name)
		if err != nil {
			t.Fatalf("archive.Create(%q) error = %v", name, err)
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			t.Fatalf("writer.Write(%q) error = %v", name, err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("archive.Close() error = %v", err)
	}
	return ispacPath
}

func testDTSX(packageName string) string {
	return `<?xml version="1.0"?>
<DTS:Executable xmlns:DTS="www.microsoft.com/SqlServer/Dts" DTS:ObjectName="` + packageName + `" DTS:ExecutableType="Microsoft.Package">
  <DTS:Executables>
    <DTS:Executable DTS:ObjectName="Load ` + packageName + `" DTS:ExecutableType="Microsoft.Pipeline">
      <DTS:ObjectData>
        <pipeline>
          <components>
            <component name="Source" componentClassID="Microsoft.OLEDBSource">
              <properties>
                <property name="OpenRowset">dbo.SourceTable</property>
              </properties>
            </component>
          </components>
        </pipeline>
      </DTS:ObjectData>
    </DTS:Executable>
  </DTS:Executables>
</DTS:Executable>`
}
