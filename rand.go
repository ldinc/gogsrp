package gogsrp

import "crypto/rand"

func ReadRand(bytes int) ([]byte, error) {
	buffer := make([]byte, bytes)
	_, err := rand.Read(bytes)
	return buffer, err
}
