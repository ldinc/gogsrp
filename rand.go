package gogsrp

import "crypto/rand"

func RandomBytes(bytes uint) ([]byte, error) {
	buffer := make([]byte, bytes)
	_, err := rand.Read(buffer)
	return buffer, err
}
