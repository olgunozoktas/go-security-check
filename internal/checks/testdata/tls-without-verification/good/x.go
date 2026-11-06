package x

import (
	"crypto/tls"
	"crypto/x509"
)

var c = &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return nil }}
var d = &tls.Config{InsecureSkipVerify: true} //go-security-check:ignore a test dialler against httptest
var e = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // a test dialler
