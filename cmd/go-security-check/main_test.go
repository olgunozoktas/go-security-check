package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// The command: exit 1 at or above -fail-on, 0 below it, 2 for a wrong flag or a folder with no go.mod; -json answers
// the counts; -only keeps the named checks. The fixture module is internal/checks/testdata/cmd (one medium finding).
var fixture = filepath.Join("..", "..", "internal", "checks", "testdata", "cmd")

func exit(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String() + errOut.String()
}

func TestExitCodes(t *testing.T) {
	if code, out := exit(t, "-only", "open-file-permissions", "-fail-on", "medium", fixture); code != 1 {
		t.Errorf("medium finding, -fail-on medium: exit %d, want 1\n%s", code, out)
	}
	if code, out := exit(t, "-only", "open-file-permissions", "-fail-on", "high", fixture); code != 0 {
		t.Errorf("medium finding, -fail-on high: exit %d, want 0\n%s", code, out)
	}
	if code, _ := exit(t, "-fail-on", "severe", fixture); code != 2 {
		t.Errorf("a wrong -fail-on: exit %d, want 2", code)
	}
	if code, _ := exit(t, filepath.Join(fixture, "nothing-here")); code != 2 {
		t.Errorf("no go.mod: exit %d, want 2", code)
	}
}

func TestJSONAndOnly(t *testing.T) {
	_, out := exit(t, "-only", "open-file-permissions", "-json", fixture)
	var got struct {
		Checks    int            `json:"checks"`
		FilesRead int            `json:"files_read"`
		Counts    map[string]int `json:"counts"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.Checks != 1 || got.FilesRead != 1 || got.Counts["medium"] != 1 {
		t.Errorf("got %+v, want 1 check, 1 file, 1 medium", got)
	}
}

func TestListNamesEveryCheck(t *testing.T) {
	if _, out := exit(t, "-list"); len(strings.Fields(out)) != 13 {
		t.Errorf("-list names %d checks, want 13", len(strings.Fields(out)))
	}
}
