// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package util

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	// Word-boundary USE (avoids matching "misUSE" in identifiers).
	reUseStatement = regexp.MustCompile(`(?i)\bUSE\s+`)
	// MySQL explicit cross-database form: `db`.`table` — first identifier is the database name.
	// Unquoted db.table is not validated (would false-positive alias.column, e.g. u.name).
	reBacktickQualified = regexp.MustCompile("`([^`]+)`\\s*\\.\\s*`([^`]+)`")
)

// ValidateSQLForDatabase checks that SQL does not switch databases or reference other
// databases by name than the configured source database.
//
// It is a heuristic (not a full SQL parser): it strips block comments, rejects USE,
// and flags obvious `other_db`.`tbl` / other_db.tbl patterns when they differ from
// the configured database name (case-insensitive). If database is empty, only USE
// is rejected; cross-database qualification is skipped.
func ValidateSQLForDatabase(sql, database string) error {
	sql = strings.TrimSpace(sql)
	database = strings.TrimSpace(database)
	if sql == "" {
		return nil
	}

	sql = reBlockComment.ReplaceAllString(sql, "")
	if err := rejectUseStatement(sql); err != nil {
		return err
	}
	if database == "" {
		return nil
	}
	return rejectForeignDatabaseQualifiers(sql, database)
}

func rejectUseStatement(sql string) error {
	if reUseStatement.MatchString(sql) {
		return fmt.Errorf("USE statements are not allowed; only the configured database may be used")
	}
	return nil
}

func rejectForeignDatabaseQualifiers(sql, allowedDB string) error {
	allowedDB = strings.TrimSpace(allowedDB)
	if allowedDB == "" {
		return nil
	}

	for _, m := range reBacktickQualified.FindAllStringSubmatch(sql, -1) {
		if len(m) < 3 {
			continue
		}
		db := strings.TrimSpace(m[1])
		if db == "" {
			continue
		}
		if strings.EqualFold(db, allowedDB) {
			continue
		}
		if isAllowedSystemSchema(db) {
			continue
		}
		return fmt.Errorf("access to database %q is not allowed; only %q is permitted", db, allowedDB)
	}

	return nil
}

// Allow read-only introspection schemas commonly used in metadata queries.
func isAllowedSystemSchema(name string) bool {
	switch strings.ToLower(name) {
	case "information_schema", "performance_schema", "mysql", "sys":
		return true
	default:
		return false
	}
}
