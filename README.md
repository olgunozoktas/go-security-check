# go-security-check

Security checks for Go modules, **without AI**: `go-security-check` reads the module's source (the standard library's
`go/ast`, no dependency, no network) and changes nothing. Each check is one file. A finding at or above `-fail-on`
(default `medium`) exits 1, so it can gate CI and a pull request.

## Install and run

```bash
go install github.com/olgunozoktas/go-security-check/cmd/go-security-check@latest
go-security-check                        # the module in this folder
go-security-check -fail-on high ./svc    # another module; fail only on high
go-security-check -json                  # for CI
go-security-check -only sql-built-from-strings,shell-with-a-variable
go-security-check -list                  # the checks
```

`-tests` also reads `_test.go` files. Exit 0: nothing at or above `-fail-on`; 1: a finding; 2: a wrong flag, or a folder
with no `go.mod`.

## What a finding means

A finding is a **candidate, not a verdict**: a check sees the shape of the code, not where a value comes from. Each one
names its file and line, why the shape is a risk, and the exact remedy. A secret is reported by its kind, never quoted.

- **high**: a live hole when the shape is what it looks like (SQL or a shell command built from a variable, a file path
  from request data, TLS without verification, a secret in the code, math/rand for a token).
- **medium**: a pattern that becomes a hole with a user's input, or an unsafe default (`template.HTML` of a variable, a
  server without timeouts, a cookie without flags, files every user can write), and a `govulncheck` that failed: the
  dependencies were not checked, so the gate fails.
- **low**: confirm it is intended. **info**: `govulncheck` is not installed.

A line that the author checked carries a marker in a real comment: `//go-security-check:ignore <reason>` (or an existing
`//nolint:gosec`). A marker inside a string counts for nothing. Certificate pinning (`InsecureSkipVerify` with
`VerifyPeerCertificate` or `VerifyConnection`) is not reported.

## The checks

| Check | What it finds |
|---|---|
| `cookie-flags` | an `http.Cookie` without `HttpOnly` or `Secure` (a deleting cookie, `MaxAge < 0`, is skipped) |
| `cors-wildcard` | `Access-Control-Allow-Origin: *`; high when the file also allows credentials |
| `govulncheck` | the Go team's `govulncheck` on the module's dependencies, when it is installed (a called vulnerable function is high; a failed run is medium) |
| `http-server-without-timeouts` | `http.ListenAndServe`, or an `http.Server` with no `ReadHeaderTimeout` or `ReadTimeout` |
| `open-file-permissions` | `os.WriteFile`, `OpenFile`, `Mkdir`, `MkdirAll`, `Chmod` with a mode that every user can write |
| `path-from-request` | `os.Open`, `ReadFile`, `filepath.Join`, `http.ServeFile` … with request data (`FormValue`, `PathValue`, `URL.Path` …) |
| `secrets-in-code` | live secret shapes in a string constant, also one joined from pieces: Stripe live keys, AWS keys, private keys, GitHub and Slack tokens |
| `shell-with-a-variable` | `exec.Command("sh", "-c", <a variable>)` |
| `sql-built-from-strings` | `Query`, `QueryRow`, `Exec`, `Prepare` (and the `Context` forms) with SQL built by `+` or `fmt.Sprintf` |
| `tls-without-verification` | `tls.Config{InsecureSkipVerify: true}` without a pinning callback |
| `unescaped-template-value` | `template.HTML`, `JS`, `URL` (medium) or `CSS` (low) of a variable |
| `weak-hash-for-passwords` | `md5` or `sha1` in a file that handles passwords |
| `weak-random-for-secrets` | a value named like a token, secret, nonce or salt from `math/rand` |

## Add a check

A file in `internal/checks/` that calls `register(name, func(m *core.Module) []core.Finding)` in its `init`, plus
`testdata/<check>/bad/x.go` (every shape it must find) and `testdata/<check>/good/x.go` (the safe forms it must leave
alone), and its entry in `checks_test.go`. `go test ./...` fails for a check without fixtures. A made-up secret in a
fixture is joined from pieces, so that no secret scanner takes it for a real one.

## License

MIT
