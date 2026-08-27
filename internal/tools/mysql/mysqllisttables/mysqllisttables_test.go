// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mysqllisttables_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googleapis/mcp-toolbox/internal/server"
	"github.com/googleapis/mcp-toolbox/internal/sources"
	"github.com/googleapis/mcp-toolbox/internal/testutils"
	"github.com/googleapis/mcp-toolbox/internal/tools"
	mysqllisttables "github.com/googleapis/mcp-toolbox/internal/tools/mysql/mysqllisttables"
	"github.com/googleapis/mcp-toolbox/internal/util/parameters"
)

func TestParseFromYamlMySQLListTables(t *testing.T) {
	ctx, err := testutils.ContextWithNewLogger()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	tcs := []struct {
		desc string
		in   string
		want server.ToolConfigs
	}{
		{
			desc: "basic example",
			in: `
            kind: tool
            name: example_tool
            type: mysql-list-tables
            source: my-mysql-instance
            description: some description
            authRequired:
                - my-google-auth-service
                - other-auth-service
			`,
			want: server.ToolConfigs{
				"example_tool": mysqllisttables.Config{
					Name:         "example_tool",
					Type:         "mysql-list-tables",
					Source:       "my-mysql-instance",
					Description:  "some description",
					AuthRequired: []string{"my-google-auth-service", "other-auth-service"},
				},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			// Parse contents
			_, _, _, got, _, _, err := server.UnmarshalResourceConfig(ctx, testutils.FormatYaml(tc.in))
			if err != nil {
				t.Fatalf("unable to unmarshal: %s", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("incorrect parse: diff %v", diff)
			}
		})
	}
}

type captureSource struct {
	sources.Source
	database  string
	response  any
	calls     int
	statement string
	params    []any
}

func (s *captureSource) MySQLPool() *sql.DB {
	return nil
}

func (s *captureSource) MySQLDatabase() string {
	return s.database
}

func (s *captureSource) RunSQL(_ context.Context, statement string, params []any) (any, error) {
	s.calls++
	s.statement = statement
	s.params = params
	return s.response, nil
}

type captureSourceProvider struct {
	source sources.Source
}

func (p captureSourceProvider) GetSource(string) (sources.Source, bool) {
	return p.source, true
}

func newListTablesTool(t *testing.T) tools.Tool {
	t.Helper()
	cfg := mysqllisttables.Config{
		Name:        "list_tables",
		Type:        "mysql-list-tables",
		Source:      "mysql-source",
		Description: "List tables",
	}
	tool, err := cfg.Initialize(nil)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	return tool
}

func TestInvokeRestrictsMetadataToConfiguredDatabase(t *testing.T) {
	ctx := context.Background()
	source := &captureSource{
		database: "HTA_MCP",
		response: []any{map[string]any{"object_name": "Ventures"}},
	}
	tool := newListTablesTool(t)
	params := parameters.ParamValues{
		{Name: "table_names", Value: "Ventures,other_database.Ventures"},
		{Name: "output_format", Value: "detailed"},
	}

	got, err := tool.Invoke(ctx, captureSourceProvider{source: source}, params, "")
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if diff := cmp.Diff(source.response, got); diff != "" {
		t.Fatalf("Invoke() response mismatch (-want +got):\n%s", diff)
	}
	if source.calls != 1 {
		t.Fatalf("RunSQL() calls = %d, want 1", source.calls)
	}
	if !strings.Contains(source.statement, "T.TABLE_SCHEMA = ?") {
		t.Errorf("query does not restrict TABLE_SCHEMA to a bound parameter")
	}
	wantParams := []any{"Ventures,other_database.Ventures", "detailed", "HTA_MCP"}
	if diff := cmp.Diff(wantParams, source.params); diff != "" {
		t.Errorf("RunSQL() parameters mismatch (-want +got):\n%s", diff)
	}

	lowerStatement := strings.ToLower(source.statement)
	for _, prohibited := range []string{
		"schema_privileges",
		"'owner'",
		"information_schema.triggers",
		"'triggers'",
		"action_statement",
		"trigger_definition",
	} {
		if strings.Contains(lowerStatement, prohibited) {
			t.Errorf("query exposes prohibited metadata %q", prohibited)
		}
	}
}

func TestInvokeRejectsEmptyConfiguredDatabase(t *testing.T) {
	for _, database := range []string{"", " \t\r\n "} {
		t.Run(database, func(t *testing.T) {
			source := &captureSource{database: database}
			tool := newListTablesTool(t)
			params := parameters.ParamValues{
				{Name: "table_names", Value: ""},
				{Name: "output_format", Value: "simple"},
			}

			_, err := tool.Invoke(context.Background(), captureSourceProvider{source: source}, params, "")
			if err == nil {
				t.Fatal("Invoke() error = nil, want configured-database error")
			}
			const want = "Table listing is unavailable because no database is configured."
			if err.Error() != want {
				t.Errorf("Invoke() error = %q, want %q", err.Error(), want)
			}
			if source.calls != 0 {
				t.Errorf("RunSQL() calls = %d, want 0", source.calls)
			}
		})
	}
}

func TestInvokePreservesOutputFormatsAndEmptyResult(t *testing.T) {
	for _, outputFormat := range []string{"simple", "detailed"} {
		t.Run(outputFormat, func(t *testing.T) {
			source := &captureSource{database: "HTA_MCP", response: []any{}}
			tool := newListTablesTool(t)
			params := parameters.ParamValues{
				{Name: "table_names", Value: ""},
				{Name: "output_format", Value: outputFormat},
			}

			got, err := tool.Invoke(context.Background(), captureSourceProvider{source: source}, params, "")
			if err != nil {
				t.Fatalf("Invoke() error = %v", err)
			}
			if diff := cmp.Diff([]any{}, got); diff != "" {
				t.Errorf("Invoke() empty response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestInvokeRejectsInvalidOutputFormat(t *testing.T) {
	source := &captureSource{database: "HTA_MCP"}
	tool := newListTablesTool(t)
	params := parameters.ParamValues{
		{Name: "table_names", Value: ""},
		{Name: "output_format", Value: "verbose"},
	}

	_, err := tool.Invoke(context.Background(), captureSourceProvider{source: source}, params, "")
	if err == nil {
		t.Fatal("Invoke() error = nil, want invalid-output-format error")
	}
	const want = `invalid value for output_format: must be 'simple' or 'detailed', but got "verbose"`
	if err.Error() != want {
		t.Errorf("Invoke() error = %q, want %q", err.Error(), want)
	}
	if source.calls != 0 {
		t.Errorf("RunSQL() calls = %d, want 0", source.calls)
	}
}
