package x

import (
	"net/http"
	"time"
)

func serve() {
	s := &http.Server{Addr: ":8081", ReadHeaderTimeout: 10 * time.Second}
	s.ListenAndServe()
}
