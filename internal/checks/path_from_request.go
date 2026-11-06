package checks

import (
	"go/ast"
	"regexp"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// A file path built from request data: "../../etc/passwd" reads any file (a path traversal).
var requestData = regexp.MustCompile(`\.(FormValue|PostFormValue|PathValue|Query\(\)\.Get|URL\.Path|URL\.Query)\b`)

func isPathCall(c *ast.CallExpr, osName, fp, http string) bool {
	return core.IsCall(c, osName, "Open", "ReadFile", "Create", "Remove", "OpenFile") || core.IsCall(c, fp, "Join") || core.IsCall(c, http, "ServeFile")
}

func init() {
	register("path-from-request", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			osName, fp, http := core.Imports(f.AST, "os"), core.Imports(f.AST, "path/filepath"), core.Imports(f.AST, "net/http")
			ast.Inspect(f.AST, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok || !isPathCall(c, osName, fp, http) {
					return true
				}
				for _, a := range c.Args {
					// One shape, one finding: os.ReadFile(filepath.Join(dir, r.FormValue("x"))) is reported at the inner Join.
					if inner, ok := a.(*ast.CallExpr); ok && isPathCall(inner, osName, fp, http) {
						continue
					}
					if requestData.MatchString(f.Text(a, m)) {
						out = append(out, m.At("path-from-request", core.High, f, c,
							"A file path is built from request data: \"../\" in it reads or writes any file.",
							"Use os.Root (os.OpenRoot(dir)) or check filepath.IsLocal on the cleaned name; serve files with http.FileServerFS."))
						break
					}
				}
				return true
			})
		}
		return out
	})
}
