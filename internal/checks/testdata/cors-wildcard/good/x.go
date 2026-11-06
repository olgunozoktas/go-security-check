package x

import "net/http"

func h(w http.ResponseWriter, origin string) { w.Header().Set("Access-Control-Allow-Origin", origin) }
