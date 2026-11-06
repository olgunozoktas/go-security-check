package checks

import (
	"go/ast"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// template.HTML(x), JS(x), URL(x) of a variable: html/template prints it without escaping (an XSS). CSS is low: a user's
// text there is styling, not script.
func init() {
	register("unescaped-template-value", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			name := core.Imports(f.AST, "html/template")
			ast.Inspect(f.AST, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok || !core.IsCall(c, name, "HTML", "JS", "URL", "HTMLAttr", "CSS", "JSStr", "Srcset") || len(c.Args) != 1 || core.IsConstant(c.Args[0]) {
					return true
				}
				s := core.Medium
				if core.Method(c) == "CSS" {
					s = core.Low
				}
				out = append(out, m.At("unescaped-template-value", s, f, c,
					"template."+core.Method(c)+"() of a variable: html/template prints it without escaping; a user's text in it is an XSS.",
					"Pass the plain string and let html/template escape it; for wanted HTML, clean it with an allow-list sanitiser first."))
				return true
			})
		}
		return out
	})
}
