package x

import "os"

func w() {
	os.WriteFile("a.txt", nil, 0o600)
	os.MkdirAll("d", 0o755)
}
