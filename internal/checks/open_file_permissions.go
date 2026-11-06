package checks

import (
	"go/ast"
	"strconv"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// A file or folder made writable by every user of the machine (0666, 0777, 0o777 …).
func init() {
	register("open-file-permissions", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			name := core.Imports(f.AST, "os")
			ast.Inspect(f.AST, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok || !core.IsCall(c, name, "WriteFile", "OpenFile", "Mkdir", "MkdirAll", "Chmod") || len(c.Args) == 0 {
					return true
				}
				lit, ok := c.Args[len(c.Args)-1].(*ast.BasicLit)
				if !ok {
					return true
				}
				if mode, err := strconv.ParseUint(lit.Value, 0, 32); err == nil && mode&0o002 != 0 {
					out = append(out, m.At("open-file-permissions", core.Medium, f, c,
						"os."+core.Method(c)+" with mode "+lit.Value+": every user of the machine can write it.",
						"Use 0o600 for a file (0o644 when others must read it) and 0o700 or 0o755 for a folder."))
				}
				return true
			})
		}
		return out
	})
}
