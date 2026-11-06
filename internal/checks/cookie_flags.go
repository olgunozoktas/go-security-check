package checks

import (
	"go/ast"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// An http.Cookie without HttpOnly (scripts read it) or without Secure (it travels over plain HTTP). A cookie with a
// negative MaxAge deletes a cookie: it carries no value to protect.
func init() {
	register("cookie-flags", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			name := core.Imports(f.AST, "net/http")
			ast.Inspect(f.AST, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !core.TypeIs(lit, name, "Cookie") {
					return true
				}
				if u, ok := core.Field(lit, "MaxAge").(*ast.UnaryExpr); ok && u.Op.String() == "-" {
					return true
				}
				var missing []string
				if v := core.Field(lit, "HttpOnly"); v == nil || !core.IsTrue(v) {
					missing = append(missing, "HttpOnly")
				}
				if v := core.Field(lit, "Secure"); v == nil || !core.IsTrue(v) {
					missing = append(missing, "Secure")
				}
				if len(missing) == 0 {
					return true
				}
				s, words := core.Low, missing[0]
				if len(missing) == 2 {
					s, words = core.Medium, "HttpOnly and Secure"
				}
				out = append(out, m.At("cookie-flags", s, f, lit, "This http.Cookie has no "+words+": scripts can read it, or it travels over plain HTTP.",
					"Set HttpOnly: true, Secure: true and SameSite: http.SameSiteLaxMode (Strict for a session)."))
				return true
			})
		}
		return out
	})
}
