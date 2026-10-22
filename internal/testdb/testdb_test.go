package testdb

import "testing"

type fakeT struct{ fatal, skipped bool }

func (f *fakeT) Helper()      {}
func (f *fakeT) Fatal(...any) { f.fatal = true }
func (f *fakeT) Skip(...any)  { f.skipped = true }

func TestDSN(t *testing.T) {
	cases := []struct {
		name, dsn, ci          string
		want                   string
		wantFatal, wantSkipped bool
	}{
		{"set", "postgres://x", "", "postgres://x", false, false},
		{"set in CI", "postgres://x", "true", "postgres://x", false, false},
		{"unset locally skips", "", "", "", false, true},
		{"unset in CI fails", "", "true", "", true, false},
	}
	for _, c := range cases {
		t.Setenv("TEST_DATABASE_URL", c.dsn)
		t.Setenv("CI", c.ci)
		f := &fakeT{}
		if got := DSN(f); got != c.want || f.fatal != c.wantFatal || f.skipped != c.wantSkipped {
			t.Errorf("%s: got %q fatal=%v skipped=%v", c.name, got, f.fatal, f.skipped)
		}
	}
}
