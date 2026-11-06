package x

import "math/rand"

func make() int {
	sessionToken := rand.Int()
	return sessionToken
}
