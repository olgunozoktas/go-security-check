package checks

import (
	"go/ast"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// tls.Config{InsecureSkipVerify: true}: any server can pretend to be the one you call. Certificate pinning (the
// default check off, and VerifyPeerCertificate or VerifyConnection checking the pin) is not reported.
func init() {
	register("tls-without-verification", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			ast.Inspect(f.AST, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				if v := core.Field(lit, "InsecureSkipVerify"); v != nil && core.IsTrue(v) && core.Field(lit, "VerifyPeerCertificate") == nil && core.Field(lit, "VerifyConnection") == nil {
					out = append(out, m.At("tls-without-verification", core.High, f, v,
						"InsecureSkipVerify is true: the TLS certificate is not checked, so any server can pretend to be this one.",
						"Remove it; for a private CA, add its certificate to RootCAs; for pinning, check the key in VerifyPeerCertificate."))
				}
				return true
			})
		}
		return out
	})
}
