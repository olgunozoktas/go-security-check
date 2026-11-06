package x

import "crypto/md5"

func checksum(b []byte) [16]byte { return md5.Sum(b) }
