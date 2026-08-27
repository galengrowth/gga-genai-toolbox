package util

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateSQLForDatabase_USE(t *testing.T) {
	t.Parallel()
	err := ValidateSQLForDatabase("USE otherdb", "mydb")
	if err == nil {
		t.Fatal("expected error for USE")
	}
	err = ValidateSQLForDatabase("select 1 /* USE x */", "mydb")
	if err != nil {
		t.Fatalf("comment should not trigger USE: %v", err)
	}
	err = ValidateSQLForDatabase("SELECT 1;\nUSE foo;", "mydb")
	if err == nil {
		t.Fatal("expected error for USE after semicolon")
	}
}

func TestValidateSQLForDatabase_backtickOtherDB(t *testing.T) {
	t.Parallel()
	err := ValidateSQLForDatabase("SELECT * FROM `other`.`t`", "mydb")
	if err == nil {
		t.Fatal("expected error for other database")
	}
	err = ValidateSQLForDatabase("SELECT * FROM `mydb`.`t`", "mydb")
	if err != nil {
		t.Fatalf("same db should pass: %v", err)
	}
	err = ValidateSQLForDatabase("SELECT * FROM `MYDB`.`t`", "mydb")
	if err != nil {
		t.Fatalf("case insensitive: %v", err)
	}
}

func TestValidateSQLForDatabase_informationSchema(t *testing.T) {
	t.Parallel()
	err := ValidateSQLForDatabase("SELECT * FROM `information_schema`.`TABLES` LIMIT 1", "mydb")
	if err != nil {
		t.Fatalf("information_schema allowed: %v", err)
	}
}

func TestValidateExecuteSQL_allowsSelect(t *testing.T) {
	t.Parallel()
	cases := []string{
		"SELECT 1",
		"SELECT id, name FROM companies LIMIT 10",
		"WITH x AS (SELECT 1 AS n) SELECT * FROM x",
		"SELECT * FROM `HTA_MCP`.`companies` WHERE name = 'information_schema'",
		"SELECT * FROM HTA_MCP.companies",
		"SELECT * FROM `hta_mcp`.companies",
		"SELECT user FROM accounts",
		"SELECT users, version, processlist, mysql FROM business_terms",
		"SELECT * FROM users",
		"SELECT * FROM version",
		"SELECT * FROM processlist",
		"SELECT * FROM mysql",
		"SELECT * FROM `mysql`",
		"SELECT c.id, m.name FROM companies AS c JOIN markets AS m ON m.id = c.market_id",
		"SELECT sector, COUNT(*) FROM companies GROUP BY sector HAVING COUNT(*) > 1",
		"SELECT id, ROW_NUMBER() OVER (PARTITION BY sector ORDER BY id) AS rn FROM companies",
		"WITH x AS (SELECT id FROM companies WHERE id IN (SELECT company_id FROM deals)) SELECT id FROM x",
		"SELECT id FROM companies UNION ALL SELECT id FROM archived_companies",
		"SELECT (SELECT MAX(id) FROM companies) AS max_id",
		"SELECT HTA_MCP.business_score(id) FROM companies",
		"SELECT ST_Buffer(POINT(0, 0), 1)",
		"SELECT some_custom_udf(1)",
		"SELECT HTA_MCP.some_fn(1)",
		"SELECT 1;;",
		"SELECT 'information_schema; VERSION() -- # /* comment */' AS literal",
		"SELECT 1 /* information_schema VERSION() ; */",
		"SELECT 1 -- information_schema VERSION() ;\n",
		"SELECT 1 # information_schema VERSION() ;\n",
		"SELECT 1--2",
	}
	for _, sql := range cases {
		if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != nil {
			t.Errorf("allowed SQL rejected: %s: %v", sql, err)
		}
	}
}

func TestValidateExecuteSQL_deniesFunctions(t *testing.T) {
	t.Parallel()
	for _, function := range deniedExecuteSQLFunctions {
		mixedCase := strings.ToUpper(function[:1]) + function[1:]
		queries := []string{
			"SELECT " + function + "()",
			"SELECT " + strings.ToUpper(function) + "()",
			"SELECT " + mixedCase + "()",
			"SELECT COALESCE(" + function + "(), 1)",
			"SELECT HTA_MCP." + function + "()",
			"SELECT " + function + "/**/()",
		}
		for _, sql := range queries {
			if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != ErrExecuteSQLUnsupported {
				t.Errorf("got %v, want ErrExecuteSQLUnsupported for %s", err, sql)
			}
		}
	}

	for _, sql := range []string{
		"SELECT CURRENT_USER",
		"SELECT CURRENT_USER()",
		"SELECT CURRENT_ROLE",
		"SELECT CURRENT_ROLE()",
	} {
		if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != ErrExecuteSQLUnsupported {
			t.Errorf("got %v, want ErrExecuteSQLUnsupported for %s", err, sql)
		}
	}
}

func TestValidateExecuteSQL_deniesAdditionalHazardFunctions(t *testing.T) {
	t.Parallel()
	cases := []string{
		"SELECT SYS_EXEC('')",
		"SELECT SYS_EVAL('')",
		"SELECT WAIT_UNTIL_SQL_THREAD_AFTER_GTIDS('', 0)",
		"SELECT MASTER_GTID_WAIT('', 0)",
		"SELECT CHARSET('x')",
		"SELECT COLLATION('x')",
		"SELECT COERCIBILITY('x')",
		"SELECT NAME_CONST('a', 1)",
		"SELECT EXTRACTVALUE('<a>1</a>', '/a')",
		"SELECT UPDATEXML('<a>1</a>', '/a', '<b>2</b>')",
		"SELECT COALESCE(EXTRACTVALUE('<a/>', '/a'), 'x')",
		"SELECT IF(1 = 1, UPDATEXML('<a/>', '/a', '<b/>'), '')",
		"SELECT HTA_MCP.EXTRACTVALUE('<a/>', '/a')",
		"SELECT EXTRACTVALUE/**/('<a/>', '/a')",
	}
	for _, sql := range cases {
		if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != ErrExecuteSQLUnsupported {
			t.Errorf("got %v, want ErrExecuteSQLUnsupported for %s", err, sql)
		}
	}
}

func TestValidateExecuteSQL_deniesProhibitedExpressionsInsideSpatialFunctions(t *testing.T) {
	t.Parallel()
	cases := []string{
		"SELECT ST_Buffer(POINT(VERSION(), 0), 1)",
		"SELECT ST_Buffer(POINT((SELECT COUNT(*) FROM information_schema.tables), 0), 1)",
	}
	for _, sql := range cases {
		if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != ErrExecuteSQLUnsupported {
			t.Errorf("got %v, want ErrExecuteSQLUnsupported for %s", err, sql)
		}
	}
}

func TestValidateExecuteSQL_deniesSchemasThroughoutAST(t *testing.T) {
	t.Parallel()
	cases := []string{
		"SELECT * FROM mysql.user",
		"SELECT * FROM `mysql`.`user`",
		"WITH x AS (SELECT * FROM information_schema.tables) SELECT * FROM x",
		"SELECT id FROM companies UNION ALL SELECT thread_id FROM performance_schema.threads",
		"SELECT (SELECT COUNT(*) FROM sys.session) AS n",
		"SELECT * FROM `information_schema`.tables",
		"SELECT * FROM performance_schema.`threads`",
		"SELECT * FROM `sys`.`session`",
		"SELECT sys.format_bytes(1)",
		"SELECT other.business_score(id) FROM companies",
		"SELECT * FROM other.companies",
		"SELECT * FROM `other`.companies",
		"SELECT * FROM other.`companies`",
		"SELECT * FROM `other`.`companies`",
	}
	for _, sql := range cases {
		if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != ErrExecuteSQLUnsupported {
			t.Errorf("got %v, want ErrExecuteSQLUnsupported for %s", err, sql)
		}
	}
}

func TestValidateExecuteSQL_deniesVariablesIntoAndLocks(t *testing.T) {
	t.Parallel()
	cases := []string{
		"SELECT @user",
		"SELECT @@session.autocommit",
		"SELECT @@global.version",
		"SELECT @captured := id FROM companies",
		"SELECT id INTO @captured FROM companies",
		"SELECT id INTO OUTFILE '/tmp/export' FROM companies",
		"SELECT id INTO DUMPFILE '/tmp/export' FROM companies",
		"SELECT * FROM companies FOR UPDATE",
		"SELECT * FROM companies FOR SHARE",
		"SELECT * FROM companies LOCK IN SHARE MODE",
	}
	for _, sql := range cases {
		if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != ErrExecuteSQLUnsupported {
			t.Errorf("got %v, want ErrExecuteSQLUnsupported for %s", err, sql)
		}
	}
}

func TestValidateExecuteSQL_deniesUnsupportedStatements(t *testing.T) {
	t.Parallel()
	cases := []string{
		"SELECT 1; SELECT 2",
		"SELECT 1;; SELECT 2",
		"SELECT (",
		"SHOW TABLES",
		"EXPLAIN SELECT * FROM companies",
		"INSERT INTO companies (name) VALUES ('x')",
		"UPDATE companies SET name = 'x'",
		"DELETE FROM companies",
		"CREATE TABLE x (id INT)",
		"TABLE companies",
		"VALUES ROW(1)",
		"SELECT 1 UNION TABLE companies",
		"SELECT 1 UNION VALUES ROW(2)",
	}
	for _, sql := range cases {
		if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != ErrExecuteSQLUnsupported {
			t.Errorf("got %v, want ErrExecuteSQLUnsupported for %s", err, sql)
		}
	}
}

func TestValidateExecuteSQL_deniesExecutableComments(t *testing.T) {
	t.Parallel()
	cases := []string{
		"SELECT 1 /*!50000 , CURRENT_USER() */",
		"SELECT 1 /*!50000 , COALESCE(VERSION(), 'unknown') */",
		"SELECT 1 /*!50000 FROM information_schema.tables */",
	}
	for _, sql := range cases {
		if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != ErrExecuteSQLUnsupported {
			t.Errorf("got %v, want ErrExecuteSQLUnsupported for %s", err, sql)
		}
	}
}

func TestValidateExecuteSQL_deniesIntrospection(t *testing.T) {
	t.Parallel()
	cases := []string{
		"SHOW FULL PROCESSLIST",
		"SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE, LEFT(INFO, 500) AS query_text FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Sleep' ORDER BY TIME DESC, ID",
		"SELECT ID, USER, DB, COMMAND, TIME, STATE, LEFT(INFO, 300) AS QUERY_TEXT FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Sleep' ORDER BY TIME DESC",
		"SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE, LEFT(INFO, 200) AS query_text FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Sleep' ORDER BY TIME DESC",
		"SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME IN ('Uptime','Threads_connected','Threads_running','Queries') LIMIT 10",
		"SELECT @@version AS server_version, @@read_only AS read_only, @@super_read_only AS super_read_only",
		"SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'HTA_MCP' LIMIT 5",
		"SELECT @@version AS server_version, @@read_only AS read_only",
		"SELECT CURRENT_USER() AS checked_at, DATABASE() AS current_database, @@read_only AS global_read_only",
		"SELECT COUNT(*) AS info_schema_tables FROM information_schema.TABLES",
		"SELECT COUNT(*) AS processlist_rows FROM information_schema.PROCESSLIST",
		"SELECT COUNT(*) AS perf_status_rows FROM performance_schema.global_status",
		"SELECT TABLE_SCHEMA, TABLE_NAME FROM `information_schema`.`TABLES` LIMIT 5",
		"SHOW VARIABLES LIKE 'version%'",
		"SHOW STATUS LIKE 'Threads%'",
		"SELECT VERSION()",
		"INSERT INTO companies (name) VALUES ('x')",
		"SELECT 1; SELECT 2",
		"USE HTA_MCP",
		"SELECT * FROM `other`.`t`",
	}
	for _, sql := range cases {
		err := ValidateExecuteSQL(sql, "HTA_MCP")
		if err == nil {
			t.Errorf("expected deny: %s", sql)
			continue
		}
		if err.Error() != ErrExecuteSQLUnsupported.Error() {
			t.Errorf("got %q, want %q for %s", err.Error(), ErrExecuteSQLUnsupported.Error(), sql)
		}
	}
}

func TestValidateExecuteSQL_deniesASTPolicyGaps(t *testing.T) {
	t.Parallel()
	cases := []string{
		"SELECT CURRENT_USER",
		"SELECT CURRENT_ROLE",
		"SELECT ICU_VERSION()",
		"SELECT LOAD_FILE('/etc/passwd')",
		"SELECT @customer_id",
		"SELECT * FROM other.companies",
		"SELECT id INTO @captured FROM companies",
		"SELECT * FROM companies FOR UPDATE",
		"SELECT 1 /*!50000 , CURRENT_USER() */",
		"SELECT (",
	}
	for _, sql := range cases {
		err := ValidateExecuteSQL(sql, "HTA_MCP")
		if err == nil {
			t.Errorf("expected deny: %s", sql)
			continue
		}
		if err != ErrExecuteSQLUnsupported {
			t.Errorf("got %v, want ErrExecuteSQLUnsupported for %s", err, sql)
		}
	}
}

func TestValidateExecuteSQL_deniesEmptyConfiguredDatabase(t *testing.T) {
	t.Parallel()
	if err := ValidateExecuteSQL("SELECT 1", ""); err != ErrExecuteSQLUnsupported {
		t.Fatalf("got %v, want ErrExecuteSQLUnsupported", err)
	}
}

func TestExecuteSQLUnsupportedMessage(t *testing.T) {
	t.Parallel()
	const want = "Only one read-only SELECT is allowed."
	if got := ErrExecuteSQLUnsupported.Error(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestValidateSQLForDatabase_emptyDatabase(t *testing.T) {
	t.Parallel()
	if err := ValidateSQLForDatabase("SELECT * FROM `x`.`y`", ""); err != nil {
		t.Fatalf("empty configured db skips qualifier check: %v", err)
	}
	if err := ValidateSQLForDatabase("USE x", ""); err == nil {
		t.Fatal("USE still rejected")
	}
}

func FuzzValidateExecuteSQL(f *testing.F) {
	for _, seed := range []string{
		"SELECT 1",
		"SELECT '",
		"SELECT `unterminated",
		"SELECT /* unterminated",
		"SELECT @x := COALESCE(VERSION(), 1)",
		"WITH x AS (SELECT * FROM information_schema.tables) SELECT * FROM x",
		"SELECT (((CURRENT_USER())))",
		"SELECT 1 /*!50000 , VERSION() */",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, sql string) {
		err := ValidateExecuteSQL(sql, "HTA_MCP")
		if err != nil && !errors.Is(err, ErrExecuteSQLUnsupported) {
			t.Fatalf("unexpected error %v for %q", err, sql)
		}
	})
}
