// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package util

import (
	"strings"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"
)

func validateExecuteSQLAST(sql, database string) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrExecuteSQLUnsupported
		}
	}()

	database = strings.TrimSpace(database)
	if database == "" {
		return ErrExecuteSQLUnsupported
	}

	statements, _, parseErr := parser.New().ParseSQL(sql)
	if parseErr != nil || len(statements) != 1 {
		return ErrExecuteSQLUnsupported
	}

	switch statement := statements[0].(type) {
	case *ast.SelectStmt:
		if statement.Kind != ast.SelectStmtKindSelect {
			return ErrExecuteSQLUnsupported
		}
	case *ast.SetOprStmt:
		// The visitor below validates every SELECT within the set operation.
	default:
		return ErrExecuteSQLUnsupported
	}

	visitor := &executeSQLASTVisitor{database: database}
	if _, ok := statements[0].Accept(visitor); !ok || visitor.denied {
		return ErrExecuteSQLUnsupported
	}
	return nil
}

type executeSQLASTVisitor struct {
	database string
	denied   bool
}

func (v *executeSQLASTVisitor) Enter(node ast.Node) (ast.Node, bool) {
	switch n := node.(type) {
	case *ast.VariableExpr:
		v.denied = true
	case *ast.SelectStmt:
		if n.Kind != ast.SelectStmtKindSelect || n.SelectIntoOpt != nil || n.LockInfo != nil {
			v.denied = true
		}
	case *ast.TableName:
		if v.isDeniedSchema(n.Schema.L) {
			v.denied = true
		}
	case *ast.FuncCallExpr:
		if v.isDeniedSchema(n.Schema.L) || isDeniedExecuteSQLFunction(n.FnName.L) {
			v.denied = true
		}
	}
	return node, v.denied
}

func (v *executeSQLASTVisitor) Leave(node ast.Node) (ast.Node, bool) {
	return node, !v.denied
}

func (v *executeSQLASTVisitor) isDeniedSchema(schema string) bool {
	if schema == "" {
		return false
	}
	return isAllowedSystemSchema(schema) || !strings.EqualFold(schema, v.database)
}

func isDeniedExecuteSQLFunction(name string) bool {
	for _, denied := range deniedExecuteSQLFunctions {
		if strings.EqualFold(name, denied) {
			return true
		}
	}
	return false
}
