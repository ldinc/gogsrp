package gogsrp

import "crypto/rand"

func ReadRand(bytes int) ([]byte, error) {
	buffer := make([]byte, bytes)
	_, err := rand.Read(buffer)
	return buffer, err
}
