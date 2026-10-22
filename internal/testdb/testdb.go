// Package testdb gives database tests one rule for a missing database.
package testdb

import "os"

// T is the part of testing.TB that DSN needs, so the rule itself can be tested.
type T interface {
	Helper()
	Fatal(args ...any)
	Skip(args ...any)
}

// DSN returns the test database URL from TEST_DATABASE_URL. Without it the test
// is skipped locally, but fails when CI is set, so a pipeline can never go green
// without having exercised the database.
func DSN(t T) string {
	t.Helper()
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		return dsn
	}
	if os.Getenv("CI") != "" {
		t.Fatal("TEST_DATABASE_URL is not set: database tests must not be skipped in CI")
		return "" // t.Fatal stops the test; this keeps fakes honest
	}
	t.Skip("TEST_DATABASE_URL not set; start the compose database and set it to run the database tests")
	return ""
}
