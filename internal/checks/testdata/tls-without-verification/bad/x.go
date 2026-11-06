package x

import "crypto/tls"

var c = &tls.Config{InsecureSkipVerify: true}

// A marker inside a string is no comment: this line is still reported.
var d = &tls.Config{InsecureSkipVerify: true, ServerName: "//nolint:gosec"}
