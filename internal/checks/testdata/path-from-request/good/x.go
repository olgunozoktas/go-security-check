package x

import (
	"net/http"
	"os"
)

func h(w http.ResponseWriter, r *http.Request) {
	root, _ := os.OpenRoot("files")
	root.Open("fixed.txt")
}
