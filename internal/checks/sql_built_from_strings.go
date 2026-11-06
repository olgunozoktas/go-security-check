package checks

import (
	"go/ast"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// The SQL argument's place for each database/sql method: 0, or 1 after the context.
var sqlArg = map[string]int{"Query": 0, "QueryRow": 0, "Exec": 0, "Prepare": 0,
	"QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1, "PrepareContext": 1}

// SQL text built from a variable ("... = " + id, fmt.Sprintf): an SQL injection when the variable comes from a request.
func init() {
	register("sql-built-from-strings", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			fmtName := core.Imports(f.AST, "fmt")
			ast.Inspect(f.AST, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				at, known := sqlArg[core.Method(call)]
				if !known || len(call.Args) <= at {
					return true
				}
				if core.Builds(call.Args[at], fmtName) {
					out = append(out, m.At("sql-built-from-strings", core.High, f, call,
						"SQL text is built from a variable: if it comes from a request, this is an SQL injection.",
						"Pass the value as a parameter: db.Query(\"... WHERE id = ?\", id) ($1 in PostgreSQL); never put it into the SQL text."))
				}
				return true
			})
		}
		return out
	})
}
