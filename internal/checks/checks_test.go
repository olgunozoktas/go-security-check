package checks

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// Each AST check: its bad shapes are ALL found at the right severity, and its good shapes (the safe form, an ignore
// marker in a real comment, certificate pinning, a deleting cookie …) are silent. testdata/<check>/bad/ and good/ hold
// the shapes; the fixtures are read where they are, and no file is written.
var want = map[string]core.Severity{
	"sql-built-from-strings": core.High, "shell-with-a-variable": core.High, "tls-without-verification": core.High,
	"http-server-without-timeouts": core.Medium, "weak-random-for-secrets": core.High, "weak-hash-for-passwords": core.High,
	"unescaped-template-value": core.Medium, "cookie-flags": core.Medium, "cors-wildcard": core.High,
	"secrets-in-code": core.High, "open-file-permissions": core.Medium, "path-from-request": core.High,
}

// How many shapes each bad fixture holds: every one of them must be found, not only the first.
var shapes = map[string]int{"sql-built-from-strings": 2, "http-server-without-timeouts": 2, "open-file-permissions": 2,
	"tls-without-verification": 2}

func run(t *testing.T, check, dir string) []core.Finding {
	t.Helper()
	m, skipped, err := core.Load(dir, false)
	if err != nil || skipped != 0 {
		t.Fatalf("%s: load: %v, %d not parsed", dir, err, skipped)
	}
	for _, c := range core.Checks() {
		if c.Name() == check {
			return m.Kept(c.Run(m))
		}
	}
	t.Fatalf("no check named %s", check)
	return nil
}

func TestEachCheckFindsTheBadShape(t *testing.T) {
	for check, severity := range want {
		got := run(t, check, filepath.Join("testdata", check, "bad"))
		n := shapes[check]
		if n == 0 {
			n = 1
		}
		if len(got) != n {
			t.Errorf("%s: %d finding(s) on bad/, want %d: %+v", check, len(got), n, got)
			continue
		}
		if got[0].Severity != severity {
			t.Errorf("%s: severity %s, want %s", check, got[0].Severity, severity)
		}
	}
}

func TestEachCheckIsSilentOnTheGoodShape(t *testing.T) {
	for check := range want {
		if got := run(t, check, filepath.Join("testdata", check, "good")); len(got) != 0 {
			t.Errorf("%s: %d finding(s) on good/: %+v", check, len(got), got)
		}
	}
}

func TestEveryCheckHasFixtures(t *testing.T) {
	for _, c := range core.Checks() {
		if _, ok := want[c.Name()]; !ok && c.Name() != "govulncheck" {
			t.Errorf("%s has no entry in want (and no testdata)", c.Name())
		}
	}
	if len(want) != len(core.Checks())-1 {
		t.Errorf("want has %d checks, the registry %d (without govulncheck)", len(want), len(core.Checks())-1)
	}
}

func TestSecretsAreNeverQuoted(t *testing.T) {
	for _, f := range run(t, "secrets-in-code", filepath.Join("testdata", "secrets-in-code", "bad")) {
		if secretShape.MatchString(f.Message + f.Remedy) {
			t.Errorf("the finding quotes the secret: %+v", f)
		}
	}
}

func govulncheck(t *testing.T, path string) []core.Finding {
	t.Helper()
	abs, _ := filepath.Abs(path)
	t.Setenv("PATH", abs)
	m, _, _ := core.Load(filepath.Join("testdata", "empty", "module"), false)
	for _, c := range core.Checks() {
		if c.Name() == "govulncheck" {
			return c.Run(m)
		}
	}
	t.Fatal("no govulncheck check")
	return nil
}

func TestGovulncheckAbsentIsInfoNeverAPass(t *testing.T) {
	got := govulncheck(t, filepath.Join("testdata", "empty", "bin"))
	if len(got) != 1 || got[0].Severity != core.Info || !strings.Contains(got[0].Message, "not installed") {
		t.Fatalf("govulncheck absent: %+v, want one info finding that says it is not installed", got)
	}
}

func TestGovulncheckFailureFailsClosed(t *testing.T) {
	got := govulncheck(t, filepath.Join("testdata", "govulncheck-fails", "bin"))
	if len(got) != 1 || got[0].Severity != core.Medium || !strings.Contains(got[0].Message, "NOT checked") {
		t.Fatalf("govulncheck exit 1: %+v, want one medium finding that says the dependencies were not checked", got)
	}
}
