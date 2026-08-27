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

package mysqlcommon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"

	driver "github.com/go-sql-driver/mysql"
	"github.com/googleapis/mcp-toolbox/internal/util"
)

// ProcessError converts database failures into safe, actionable tool errors.
func ProcessError(err error) util.ToolboxError {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return util.NewAgentError("The query timed out. Add filters or request fewer rows.", nil)
	}

	var mysqlErr *driver.MySQLError
	if errors.As(err, &mysqlErr) {
		switch mysqlErr.Number {
		case 1054:
			return util.NewAgentError("A column was not found. Use list_tables to verify column names.", nil)
		case 1064:
			return util.NewAgentError("The query has invalid MySQL syntax. Check it and try again.", nil)
		case 1146:
			return util.NewAgentError("A table was not found. Use list_tables to verify table names.", nil)
		case 1044, 1045:
			return util.NewAgentError("The database connection is not authorized. Contact support.", nil)
		case 1142, 1143, 1227, 1370:
			return util.NewAgentError("The database does not allow the requested table or function.", nil)
		case 1205, 3024:
			return util.NewAgentError("The query timed out. Add filters or request fewer rows.", nil)
		}
	}

	return util.NewAgentError("The database could not complete the query. Try again later.", nil)
}

// ConvertToType handles casting mysql returns to the right type
// types for mysql driver: https://github.com/go-sql-driver/mysql/blob/v1.9.3/fields.go
// all numeric type or unknown type will be return as is.
func ConvertToType(t *sql.ColumnType, v any) (any, error) {
	switch t.ScanType() {
	case reflect.TypeOf(""), reflect.TypeOf([]byte{}), reflect.TypeOf(sql.NullString{}):
		// unmarshal JSON data before returning to prevent double marshaling
		if t.DatabaseTypeName() == "JSON" {
			// unmarshal JSON data before storing to prevent double marshaling
			var unmarshaledData any
			err := json.Unmarshal(v.([]byte), &unmarshaledData)
			if err != nil {
				return nil, err
			}
			return unmarshaledData, nil
		}
		return string(v.([]byte)), nil
	default:
		return v, nil
	}
}
