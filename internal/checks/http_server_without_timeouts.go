package checks

import (
	"go/ast"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// http.ListenAndServe, or an http.Server with no ReadHeaderTimeout or ReadTimeout: slow clients (Slowloris) hold its connections.
func init() {
	register("http-server-without-timeouts", func(m *core.Module) []core.Finding {
		var out []core.Finding
		remedy := "Use &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: …, WriteTimeout: …, IdleTimeout: …}."
		for _, f := range m.Files {
			httpName := core.Imports(f.AST, "net/http")
			ast.Inspect(f.AST, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.CallExpr:
					if core.IsCall(v, httpName, "ListenAndServe", "ListenAndServeTLS") {
						out = append(out, m.At("http-server-without-timeouts", core.Medium, f, v,
							"http.ListenAndServe has no timeouts: slow clients can hold every connection.", remedy))
					}
				case *ast.CompositeLit:
					if core.TypeIs(v, httpName, "Server") && core.Field(v, "ReadHeaderTimeout") == nil && core.Field(v, "ReadTimeout") == nil {
						out = append(out, m.At("http-server-without-timeouts", core.Medium, f, v,
							"This http.Server has no ReadHeaderTimeout or ReadTimeout: slow clients can hold every connection.", remedy))
					}
				}
				return true
			})
		}
		return out
	})
}
