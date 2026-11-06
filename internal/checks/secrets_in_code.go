package checks

import (
	"go/ast"
	"regexp"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

// The shapes of live secrets: Stripe live keys, AWS access keys, private keys, GitHub and Slack tokens.
var secretShape = regexp.MustCompile(`(?:sk|rk)_live_[0-9A-Za-z]{16,}|whsec_[0-9A-Za-z]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{40,}|xox[bpas]-[0-9A-Za-z-]{20,}`)

// A live secret in a string constant, also one joined from pieces ("sk_" + "live_…"): the check reads the joined value.
func init() {
	register("secrets-in-code", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			ast.Inspect(f.AST, func(n ast.Node) bool {
				e, ok := n.(ast.Expr)
				if !ok {
					return true
				}
				switch e.(type) {
				case *ast.BasicLit, *ast.BinaryExpr:
				default:
					return true
				}
				s, ok := core.ConstString(e)
				if !ok || !secretShape.MatchString(s) {
					return true
				}
				// The finding names the kind, never the value: a secret must not land in a log.
				out = append(out, m.At("secrets-in-code", core.High, f, e, "A live secret is written into the source.",
					"Revoke it at its provider now (it is in the git history), then read the new one from the environment."))
				return false // one finding for the whole joined string
			})
		}
		return out
	})
}
