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

func TestValidateSQLForDatabase_emptyDatabase(t *testing.T) {
	t.Parallel()
	if err := ValidateSQLForDatabase("SELECT * FROM `x`.`y`", ""); err != nil {
		t.Fatalf("empty configured db skips qualifier check: %v", err)
	}
	if err := ValidateSQLForDatabase("USE x", ""); err == nil {
		t.Fatal("USE still rejected")
	}
}
