package x

import (
	"net/http"
	"os"
	"path/filepath"
)

func h(w http.ResponseWriter, r *http.Request) {
	os.ReadFile(filepath.Join("files", r.FormValue("name")))
}
