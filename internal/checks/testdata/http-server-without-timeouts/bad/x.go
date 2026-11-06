package x

import "net/http"

func serve() {
	http.ListenAndServe(":8080", nil)
	s := &http.Server{Addr: ":8081"}
	s.ListenAndServe()
}
