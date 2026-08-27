// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package mysqlcommon

import (
	"context"
	"errors"
	"fmt"
	"testing"

	driver "github.com/go-sql-driver/mysql"
)

func TestProcessErrorReturnsSafeActionableMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "syntax",
			err:  &driver.MySQLError{Number: 1064, Message: "raw parser details"},
			want: "The query has invalid MySQL syntax. Check it and try again.",
		},
		{
			name: "unknown table",
			err:  &driver.MySQLError{Number: 1146, Message: "Table 'private.secret' doesn't exist"},
			want: "A table was not found. Use list_tables to verify table names.",
		},
		{
			name: "unknown column",
			err:  &driver.MySQLError{Number: 1054, Message: "Unknown column 'secret'"},
			want: "A column was not found. Use list_tables to verify column names.",
		},
		{
			name: "permission",
			err:  fmt.Errorf("wrapped: %w", &driver.MySQLError{Number: 1370, Message: "execute denied to 'hta-mcp'@'%'"}),
			want: "The database does not allow the requested table or function.",
		},
		{
			name: "connection authorization",
			err:  &driver.MySQLError{Number: 1045, Message: "Access denied for user 'hta-mcp'@'%'"},
			want: "The database connection is not authorized. Contact support.",
		},
		{
			name: "timeout",
			err:  fmt.Errorf("wrapped: %w", context.DeadlineExceeded),
			want: "The query timed out. Add filters or request fewer rows.",
		},
		{
			name: "unexpected",
			err:  errors.New("dial tcp internal-db.example:3306: connection refused"),
			want: "The database could not complete the query. Try again later.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ProcessError(tc.err)
			if got.Error() != tc.want {
				t.Fatalf("got %q, want %q", got.Error(), tc.want)
			}
		})
	}
}
