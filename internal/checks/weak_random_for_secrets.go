package checks

import (
	"go/ast"
	"regexp"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

var secretName = regexp.MustCompile(`(?i)token|secret|nonce|salt|otp|password|apikey|api_key|session`)

// math/rand for a token, a secret, a nonce or a salt: its values can be predicted.
func init() {
	register("weak-random-for-secrets", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			name := core.Imports(f.AST, "math/rand")
			if name == "" {
				name = core.Imports(f.AST, "math/rand/v2")
			}
			if name == "" {
				continue
			}
			ast.Inspect(f.AST, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				uses := false
				for _, r := range as.Rhs {
					ast.Inspect(r, func(x ast.Node) bool {
						if c, ok := x.(*ast.CallExpr); ok {
							if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
								if id, ok := sel.X.(*ast.Ident); ok && id.Name == name {
									uses = true
								}
							}
						}
						return true
					})
				}
				for _, l := range as.Lhs {
					if id, ok := l.(*ast.Ident); ok && uses && secretName.MatchString(id.Name) {
						out = append(out, m.At("weak-random-for-secrets", core.High, f, as,
							"A value named like a secret ("+id.Name+") comes from math/rand: it can be predicted.",
							"Use crypto/rand (rand.Text() for a token, rand.Read for bytes)."))
					}
				}
				return true
			})
		}
		return out
	})
}
