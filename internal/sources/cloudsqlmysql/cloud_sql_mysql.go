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

package cloudsqlmysql

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"slices"
	"time"

	"cloud.google.com/go/cloudsqlconn/mysql/mysql"
	"github.com/goccy/go-yaml"
	"github.com/googleapis/mcp-toolbox/internal/sources"
	"github.com/googleapis/mcp-toolbox/internal/tools/mysql/mysqlcommon"
	"github.com/googleapis/mcp-toolbox/internal/util"
	"github.com/googleapis/mcp-toolbox/internal/util/orderedmap"
	"go.opentelemetry.io/otel/trace"
)

const SourceType string = "cloud-sql-mysql"

// validate interface
var _ sources.SourceConfig = Config{}

func init() {
	if !sources.Register(SourceType, newConfig) {
		panic(fmt.Sprintf("source type %q already registered", SourceType))
	}
}

func newConfig(ctx context.Context, name string, decoder *yaml.Decoder) (sources.SourceConfig, error) {
	actual := Config{Name: name, IPType: "public"} // Default IPType
	if err := decoder.DecodeContext(ctx, &actual); err != nil {
		return nil, err
	}
	return actual, nil
}

type Config struct {
	Name     string         `yaml:"name" validate:"required"`
	Type     string         `yaml:"type" validate:"required"`
	Project  string         `yaml:"project" validate:"required"`
	Region   string         `yaml:"region" validate:"required"`
	Instance string         `yaml:"instance" validate:"required"`
	IPType   sources.IPType `yaml:"ipType"`
	User     string         `yaml:"user"`
	Password string         `yaml:"password"`
	Database string         `yaml:"database"`
	// Fork: parity with internal/sources/mysql — readTimeout + extra DSN params for go-sql-driver/mysql over Cloud SQL connector.
	QueryTimeout string            `yaml:"queryTimeout"`
	QueryParams  map[string]string `yaml:"queryParams"`
}

func (r Config) SourceConfigType() string {
	return SourceType
}

func (r Config) Initialize(ctx context.Context, tracer trace.Tracer) (sources.Source, error) {
	pool, err := initCloudSQLMySQLConnectionPool(ctx, tracer, r.Name, r.Project, r.Region, r.Instance, r.IPType.String(), r.User, r.Password, r.Database, r.QueryTimeout, r.QueryParams)
	if err != nil {
		return nil, fmt.Errorf("unable to create pool: %w", err)
	}

	err = pool.PingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to connect successfully: %w", err)
	}

	s := &Source{
		Config: r,
		Pool:   pool,
	}
	return s, nil
}

var _ sources.Source = &Source{}

type Source struct {
	Config
	Pool *sql.DB
}

func (s *Source) SourceType() string {
	return SourceType
}

// DatabaseName returns the configured database name for this source.
func (s *Source) DatabaseName() string {
	return s.Config.Database
}

func (s *Source) ToConfig() sources.SourceConfig {
	return s.Config
}

func (s *Source) MySQLPool() *sql.DB {
	return s.Pool
}

func (s *Source) MySQLDatabase() string {
	return s.Database
}

func (s *Source) RunSQL(ctx context.Context, statement string, params []any) (any, error) {
	results, err := s.MySQLPool().QueryContext(ctx, statement, params...)
	if err != nil {
		return nil, fmt.Errorf("unable to execute query: %w", err)
	}
	defer results.Close()

	cols, err := results.Columns()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve rows column name: %w", err)
	}

	// create an array of values for each column, which can be re-used to scan each row
	rawValues := make([]any, len(cols))
	values := make([]any, len(cols))
	for i := range rawValues {
		values[i] = &rawValues[i]
	}

	colTypes, err := results.ColumnTypes()
	if err != nil {
		return nil, fmt.Errorf("unable to get column types: %w", err)
	}

	var out []any
	for results.Next() {
		err := results.Scan(values...)
		if err != nil {
			return nil, fmt.Errorf("unable to parse row: %w", err)
		}
		row := orderedmap.Row{}
		for i, name := range cols {
			val := rawValues[i]
			if val == nil {
				row.Add(name, nil)
				continue
			}

			convertedValue, err := mysqlcommon.ConvertToType(colTypes[i], val)
			if err != nil {
				return nil, fmt.Errorf("errors encountered when converting values: %w", err)
			}
			row.Add(name, convertedValue)
		}
		out = append(out, row)
	}

	if err := results.Err(); err != nil {
		return nil, fmt.Errorf("errors encountered during row iteration: %w", err)
	}

	return out, nil
}

func getConnectionConfig(ctx context.Context, user, pass string) (string, string, bool, error) {
	useIAM := true

	// If username and password both provided, use password authentication
	if user != "" && pass != "" {
		useIAM = false
		return user, pass, useIAM, nil
	}

	// If username is empty, fetch email from ADC
	// otherwise, use username as IAM email
	if user == "" {
		if pass != "" {
			return "", "", useIAM, fmt.Errorf("password is provided without a username. Please provide both a username and password, or leave both fields empty")
		}
		email, err := sources.GetIAMPrincipalEmailFromADC(ctx, "mysql")
		if err != nil {
			return "", "", useIAM, fmt.Errorf("error getting email from ADC: %v", err)
		}
		user = email
	}

	// Pass the user, empty password and useIAM set to true
	return user, pass, useIAM, nil
}

func initCloudSQLMySQLConnectionPool(ctx context.Context, tracer trace.Tracer, name, project, region, instance, ipType, user, pass, dbname, queryTimeout string, queryParams map[string]string) (*sql.DB, error) {
	//nolint:all // Reassigned ctx
	ctx, span := sources.InitConnectionSpan(ctx, tracer, SourceType, name)
	defer span.End()

	// Configure the driver to connect to the database
	user, pass, useIAM, err := getConnectionConfig(ctx, user, pass)
	if err != nil {
		return nil, fmt.Errorf("unable to get Cloud SQL connection config: %w", err)
	}

	// Create a new dialer with options
	userAgent, err := util.UserAgentFromContext(ctx)
	if err != nil {
		return nil, err
	}
	opts, err := sources.GetCloudSQLOpts(ipType, userAgent, useIAM)
	if err != nil {
		return nil, err
	}

	// Use a unique driver name based on the source name.
	driverName := fmt.Sprintf("cloudsql-mysql-%s", name)

	if !slices.Contains(sql.Drivers(), driverName) {
		if _, err := mysql.RegisterDriver(driverName, opts...); err != nil {
			return nil, fmt.Errorf("unable to register driver: %w", err)
		}
	}

	pathPrefix, err := cloudSQLMySQLDSNPathPrefix(useIAM, user, pass, driverName, project, region, instance, dbname)
	if err != nil {
		return nil, err
	}
	query, err := cloudSQLMySQLDSNQuery(userAgent, queryTimeout, queryParams)
	if err != nil {
		return nil, err
	}
	dsn := pathPrefix + "?" + query

	db, err := sql.Open(
		driverName,
		dsn,
	)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// cloudSQLMySQLDSNPathPrefix returns the DSN path before the query string (user@driver(project:region:instance)/db).
func cloudSQLMySQLDSNPathPrefix(useIAM bool, user, pass, driverName, project, region, instance, dbname string) (string, error) {
	if useIAM {
		return fmt.Sprintf("%s@%s(%s:%s:%s)/%s", user, driverName, project, region, instance, dbname), nil
	}
	return fmt.Sprintf("%s:%s@%s(%s:%s:%s)/%s", user, pass, driverName, project, region, instance, dbname), nil
}

// cloudSQLMySQLDSNQuery builds the go-sql-driver/mysql query segment, matching internal/sources/mysql semantics:
// default parseTime=true, merge queryParams (skip empty), then set readTimeout from queryTimeout (same validation as mysql source).
func cloudSQLMySQLDSNQuery(userAgent, queryTimeout string, queryParams map[string]string) (string, error) {
	v := url.Values{}
	v.Set("connectionAttributes", fmt.Sprintf("program_name:%s", userAgent))
	v.Set("parseTime", "true")
	for k, val := range queryParams {
		if val == "" {
			continue
		}
		v.Set(k, val)
	}
	if queryTimeout != "" {
		if _, err := time.ParseDuration(queryTimeout); err != nil {
			return "", fmt.Errorf("invalid queryTimeout %q: %w", queryTimeout, err)
		}
		v.Set("readTimeout", queryTimeout)
	}
	return v.Encode(), nil
}
