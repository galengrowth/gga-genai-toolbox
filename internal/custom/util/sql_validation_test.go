package util

import "testing"

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
		"SELECT id, name FROM companies LIMIT 10",
		"WITH x AS (SELECT 1 AS n) SELECT * FROM x",
		"SELECT * FROM `HTA_MCP`.`companies` WHERE name = 'information_schema'",
		"SELECT user FROM accounts",
	}
	for _, sql := range cases {
		if err := ValidateExecuteSQL(sql, "HTA_MCP"); err != nil {
			t.Errorf("allowed SQL rejected: %s: %v", sql, err)
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

func TestValidateSQLForDatabase_emptyDatabase(t *testing.T) {
	t.Parallel()
	if err := ValidateSQLForDatabase("SELECT * FROM `x`.`y`", ""); err != nil {
		t.Fatalf("empty configured db skips qualifier check: %v", err)
	}
	if err := ValidateSQLForDatabase("USE x", ""); err == nil {
		t.Fatal("USE still rejected")
	}
}
