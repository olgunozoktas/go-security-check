# False findings: template.JS of a constant, and template.URL of a base64 data: address

Created: 2026-11-07 01:00:00 (UTC+3)
Priority: **P3**
Tags: bug, back-end
Size: S
Repository: go-security-check
GitHub Issue: none (this item is a file only)
Status legend: `- [ ]` = to do, `- [x]` = implemented

## Context

`unescaped-template-value` reports every `template.JS/HTML/URL(x)` whose argument is not a literal, as medium. Two
shapes are safe by construction, and a person who checks them marks them `//go-security-check:ignore` each time:

```go
const pageScript = `…`
data := tmplData{Script: template.JS(pageScript)}                                    // a package-level constant

img := template.URL("data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(b)) // base64 is the only variable part
```

Base64 output holds only `A–Z a–z 0–9 + / =`: it cannot carry a quote, `<` or a `javascript:` scheme.

## Items

- [ ] **[back-end] Do not report a constant:** `template.JS/HTML/URL/CSS/HTMLAttr(x)` where `x` is a constant, a
  string literal, or a concatenation of them, is no finding.
  - Tests / done when: a fixture with `template.JS(constScript)` gives no finding; `template.JS(userInput)` still does.
- [ ] **[back-end] A base64 data: address is low, not medium:** `template.URL("data:<literal type>;base64," +
  base64.StdEncoding.EncodeToString(…))` gives at most a low finding ("confirm it is intended").
  - Tests / done when: that fixture gives a low finding; `template.URL("data:" + userType + "," + raw)` stays medium.

## Acceptance

- The two fixtures above: no finding for the constant, a low finding for the base64 data: address, and the user-input
  cases stay medium.
