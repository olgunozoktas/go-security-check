package x

import "net/http"

var c = &http.Cookie{Name: "session", Value: "v", HttpOnly: true, Secure: true}
var gone = &http.Cookie{Name: "session", MaxAge: -1}
