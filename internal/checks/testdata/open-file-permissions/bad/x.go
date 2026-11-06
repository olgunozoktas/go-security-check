package x

import "os"

func w() {
	os.WriteFile("a.txt", nil, 0o666)
	os.MkdirAll("d", 0777)
}
