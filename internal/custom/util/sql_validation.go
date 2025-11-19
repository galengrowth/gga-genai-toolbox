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

package util

import (
	"fmt"
	"strings"
)

// ValidateSQLForDatabase checks if the SQL query attempts to access databases other than the configured one.
func ValidateSQLForDatabase(sql, database string) error {
	// Reject USE statements
	if strings.Contains(strings.ToUpper(sql), "USE ") {
		return fmt.Errorf("USE statements are not allowed")
	}
	// Simple check for db.table references where db != configured database
	// This is basic; a full parser would be better, but this covers common cases
	parts := strings.Split(sql, "`")
	for i := 0; i < len(parts)-1; i += 2 { // even indices are outside backticks
		segment := parts[i]
		// Look for db.table patterns
		if strings.Contains(segment, ".") {
			words := strings.FieldsFunc(segment, func(r rune) bool {
				return r == '.' || r == ' ' || r == '\t' || r == '\n' || r == '(' || r == ')'
			})
			for j, word := range words {
				if word == "." && j > 0 && j < len(words)-1 {
					db := words[j-1]
					if db != database && db != "" {
						return fmt.Errorf("access to database %q is not allowed; only %q is permitted", db, database)
					}
				}
			}
		}
	}
	return nil
}
