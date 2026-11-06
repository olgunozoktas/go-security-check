package checks

import (
	"bytes"
	"go/ast"
	"strconv"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// Access-Control-Allow-Origin: * — every site may read the answers; with credentials allowed in the file it is high.
func init() {
	register("cors-wildcard", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			withCredentials := bytes.Contains(f.Src, []byte(`"Access-Control-Allow-Credentials"`))
			ast.Inspect(f.AST, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok || (core.Method(c) != "Set" && core.Method(c) != "Add") || len(c.Args) != 2 {
					return true
				}
				k, _ := c.Args[0].(*ast.BasicLit)
				v, _ := c.Args[1].(*ast.BasicLit)
				if k == nil || v == nil {
					return true
				}
				key, _ := strconv.Unquote(k.Value)
				val, _ := strconv.Unquote(v.Value)
				if key != "Access-Control-Allow-Origin" || val != "*" {
					return true
				}
				s, msg := core.Low, "CORS allows every origin (*): any site can read these answers."
				if withCredentials {
					s, msg = core.High, "CORS allows every origin (*) in a file that also allows credentials: any site can act as the signed-in user."
				}
				out = append(out, m.At("cors-wildcard", s, f, c, msg, "Answer with the request's Origin only when it is in an allow-list, and add Vary: Origin."))
				return true
			})
		}
		return out
	})
}
