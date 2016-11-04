package gogsrp

import "crypto/rand"

func ReadRand(n int) ([]byte, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	return bytes, err
}
