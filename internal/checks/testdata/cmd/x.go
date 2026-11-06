package x

import "os"

func w() { os.WriteFile("a.txt", nil, 0o666) }
