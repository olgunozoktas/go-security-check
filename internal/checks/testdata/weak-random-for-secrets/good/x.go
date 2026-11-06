package x

import "math/rand"

func pick() int {
	jitter := rand.Intn(100)
	return jitter
}
