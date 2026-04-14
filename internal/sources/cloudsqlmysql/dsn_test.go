// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cloudsqlmysql

import (
	"net/url"
	"strings"
	"testing"
)

func TestCloudSQLMySQLDSNQuery(t *testing.T) {
	t.Parallel()
	q, err := cloudSQLMySQLDSNQuery("my-ua", "30s", map[string]string{"tls": "skip-verify"})
	if err != nil {
		t.Fatal(err)
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	if vals.Get("parseTime") != "true" {
		t.Fatalf("parseTime: %q", vals.Get("parseTime"))
	}
	if vals.Get("readTimeout") != "30s" {
		t.Fatalf("readTimeout: %q", vals.Get("readTimeout"))
	}
	if vals.Get("tls") != "skip-verify" {
		t.Fatalf("tls: %q", vals.Get("tls"))
	}
	if !strings.Contains(vals.Get("connectionAttributes"), "program_name:my-ua") {
		t.Fatalf("connectionAttributes: %q", vals.Get("connectionAttributes"))
	}
}

func TestCloudSQLMySQLDSNQuery_invalidTimeout(t *testing.T) {
	t.Parallel()
	_, err := cloudSQLMySQLDSNQuery("ua", "not-a-duration", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}
