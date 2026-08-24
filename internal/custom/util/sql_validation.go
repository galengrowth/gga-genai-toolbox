// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package util

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrExecuteSQLUnsupported is the client-facing error for mysql-execute-sql denials.
var ErrExecuteSQLUnsupported = errors.New("this operation is not supported")

var (
	reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reLineComment  = regexp.MustCompile(`(?m)--[^\n]*`)
	reHashComment  = regexp.MustCompile(`(?m)#[^\n]*`)
	reSingleQuoted = regexp.MustCompile(`'(?:\\.|''|[^'\\])*'`)
	reDoubleQuoted = regexp.MustCompile(`"(?:\\.|""|[^"\\])*"`)
	// Word-boundary USE (avoids matching "misUSE" in identifiers).
	reUseStatement = regexp.MustCompile(`(?i)\bUSE\s+`)
	// MySQL explicit cross-database form: `db`.`table` — first identifier is the database name.
	// Unquoted db.table is not validated (would false-positive alias.column, e.g. u.name).
	reBacktickQualified = regexp.MustCompile("`([^`]+)`\\s*\\.\\s*`([^`]+)`")
	reSelectOrWith = regexp.MustCompile(`(?i)^\s*(WITH|SELECT)\b`)
	reProcesslist  = regexp.MustCompile(`(?i)\bPROCESSLIST\b`)
	reSystemVar         = regexp.MustCompile(`@@`)
	reIntrospectFn      = regexp.MustCompile(`(?i)\b(?:CURRENT_USER|SESSION_USER|SYSTEM_USER|DATABASE|SCHEMA|VERSION|CONNECTION_ID|USER)\s*\(`)
	reIntoDump          = regexp.MustCompile(`(?i)\bINTO\s+(?:OUTFILE|DUMPFILE)\b`)
	reSystemSchema      = regexp.MustCompile("(?i)(?:\\binformation_schema\\b|\\bperformance_schema\\b|`mysql`|`sys`|\\bmysql\\s*\\.|\\bsys\\s*\\.)")
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

// ValidateExecuteSQL applies ChatGPT / public-MCP guardrails on user-supplied SQL for
// mysql-execute-sql. list_tables (and other tools) keep using ValidateSQLForDatabase
// only, so they may still query INFORMATION_SCHEMA internally.
//
// Allowed: a single SELECT or WITH ... SELECT against the configured database.
// Denied: SHOW, PROCESSLIST, system schemas, @@vars, session/user introspection
// functions, USE, and other-database qualifiers.
func ValidateExecuteSQL(sql, database string) error {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return ErrExecuteSQLUnsupported
	}

	if err := ValidateSQLForDatabase(sql, database); err != nil {
		return ErrExecuteSQLUnsupported
	}

	stripped := stripSQLNoise(sql)
	if stripped == "" {
		return ErrExecuteSQLUnsupported
	}

	if !reSelectOrWith.MatchString(stripped) ||
		hasTrailingStatement(stripped) ||
		reProcesslist.MatchString(stripped) ||
		reSystemSchema.MatchString(stripped) ||
		reSystemVar.MatchString(stripped) ||
		reIntrospectFn.MatchString(stripped) ||
		reIntoDump.MatchString(stripped) {
		return ErrExecuteSQLUnsupported
	}
	return nil
}

func stripSQLNoise(sql string) string {
	sql = reBlockComment.ReplaceAllString(sql, " ")
	sql = reLineComment.ReplaceAllString(sql, " ")
	sql = reHashComment.ReplaceAllString(sql, " ")
	sql = reSingleQuoted.ReplaceAllString(sql, "''")
	sql = reDoubleQuoted.ReplaceAllString(sql, `""`)
	return strings.TrimSpace(sql)
}

func hasTrailingStatement(sql string) bool {
	// Ignore a single trailing semicolon on an otherwise single statement.
	trimmed := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(sql), ";"))
	return strings.Contains(trimmed, ";")
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
