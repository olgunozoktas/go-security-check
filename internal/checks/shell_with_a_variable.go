package checks

import (
	"go/ast"
	"strconv"

	"github.com/olgunozoktas/go-security-check/internal/core"
)

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "/bin/sh": true, "/bin/bash": true, "cmd": true}

// exec.Command("sh", "-c", <a variable>): a command injection when the variable holds user input.
func init() {
	register("shell-with-a-variable", func(m *core.Module) []core.Finding {
		var out []core.Finding
		for _, f := range m.Files {
			execName := core.Imports(f.AST, "os/exec")
			ast.Inspect(f.AST, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !core.IsCall(call, execName, "Command", "CommandContext") {
					return true
				}
				args := call.Args
				if core.Method(call) == "CommandContext" && len(args) > 0 {
					args = args[1:]
				}
				if len(args) < 3 {
					return true
				}
				shell, _ := args[0].(*ast.BasicLit)
				flag, _ := args[1].(*ast.BasicLit)
				if shell == nil || flag == nil {
					return true
				}
				s, _ := strconv.Unquote(shell.Value)
				fl, _ := strconv.Unquote(flag.Value)
				if shells[s] && (fl == "-c" || fl == "/C" || fl == "/c") && !core.IsConstant(args[2]) {
					out = append(out, m.At("shell-with-a-variable", core.High, f, call,
						"A shell runs a command line built from a variable: a command injection when it holds user input.",
						"Run the program itself with its arguments: exec.Command(\"git\", \"log\", ref); never through \"sh -c\"."))
				}
				return true
			})
		}
		return out
	})
}
