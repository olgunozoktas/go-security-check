package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// govulncheck: the Go team's check of the module's dependencies against the Go vulnerability database (it needs the
// network). Absent: an info finding. FAIL CLOSED (the security review of 2026-11-06): exit 0 (clean) and 3 (found) are
// answers; any other exit, or output with no "config" message, is a medium finding, so the default gate fails.
func init() {
	register("govulncheck", func(m *core.Module) []core.Finding {
		bin, err := exec.LookPath("govulncheck")
		if err != nil {
			return []core.Finding{{Check: "govulncheck", Severity: core.Info, Level: "info", File: "go.mod",
				Message: "govulncheck did not run: it is not installed, so the dependencies were not checked.",
				Remedy:  "go install golang.org/x/vuln/cmd/govulncheck@latest"}}
		}
		cmd := exec.Command(bin, "-format", "json", "./...")
		cmd.Dir = m.Root
		raw, err := cmd.Output()
		code := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else if err != nil {
			code = -1
		}
		failed := func(why string) []core.Finding {
			return []core.Finding{{Check: "govulncheck", Severity: core.Medium, Level: "medium", File: "go.mod",
				Message: "govulncheck failed (" + why + "): the dependencies were NOT checked.",
				Remedy:  "Run govulncheck ./... by hand and fix what stops it (the network, a build error)."}}
		}
		if code != 0 && code != 3 {
			return failed(fmt.Sprintf("exit %d", code))
		}
		seen, sawConfig := map[string]bool{}, false
		var out []core.Finding
		dec := json.NewDecoder(bytes.NewReader(raw))
		for {
			var msg struct {
				Config  json.RawMessage `json:"config"`
				Finding *struct {
					OSV   string `json:"osv"`
					Trace []struct {
						Module   string `json:"module"`
						Function string `json:"function"`
					} `json:"trace"`
				} `json:"finding"`
			}
			if err := dec.Decode(&msg); err == io.EOF {
				break
			} else if err != nil {
				return failed("unreadable output")
			}
			sawConfig = sawConfig || len(msg.Config) > 0
			if msg.Finding == nil || len(msg.Finding.Trace) == 0 || msg.Finding.Trace[0].Function == "" || seen[msg.Finding.OSV] {
				continue // only a called vulnerable function affects the code
			}
			seen[msg.Finding.OSV] = true
			out = append(out, core.Finding{Check: "govulncheck", Severity: core.High, Level: "high", File: "go.mod",
				Message: msg.Finding.OSV + " in " + msg.Finding.Trace[0].Module + ": the code calls the vulnerable function.",
				Remedy:  "Update the module (go get <module>@latest && go mod tidy); read https://pkg.go.dev/vuln/" + msg.Finding.OSV + "."})
		}
		if !sawConfig {
			return failed("no config message in its output")
		}
		return out
	})
}
