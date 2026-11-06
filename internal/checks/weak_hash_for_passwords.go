package checks

import (
	"go/ast"
	"regexp"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

var passwordWord = regexp.MustCompile(`(?i)password|passwd|pwd`)

// md5 or sha1 in a file that handles passwords: a fast hash is brute-forced in hours.
func init() {
	register("weak-hash-for-passwords", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			if !passwordWord.Match(f.Src) {
				continue
			}
			for _, path := range []string{"crypto/md5", "crypto/sha1"} {
				name := core.Imports(f.AST, path)
				ast.Inspect(f.AST, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok && core.IsCall(c, name, "Sum", "New") {
						out = append(out, m.At("weak-hash-for-passwords", core.High, f, c,
							path+" in a file that handles passwords: a fast hash is brute-forced in hours.",
							"Hash passwords with golang.org/x/crypto/bcrypt or argon2id; keep md5/sha1 only for checksums."))
					}
					return true
				})
			}
		}
		return out
	})
}
