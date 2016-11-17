package gogsrp

import (
	"hash"
	"math/big"
)

func Pad(data []byte, length int) []byte {
	n := len(data)
	if n > length {
		return data
	}
	padded := make([]byte, length)
	copy(padded[length-n:], data)
	return padded
}

func CommonHash(clientPK, serverPK *big.Int, newHash func() hash.Hash) (*big.Int, error) {
	clientBytes := clientPK.Bytes()
	serverBytes := serverPK.Bytes()
	hash := newHash()
	hash.Write(Pad(clientBytes, len(serverBytes)))
	hash.Write(Pad(serverBytes, len(clientBytes)))
	u := new(big.Int).SetBytes(hash.Sum(nil))
	return u, nil
}

func SessionKey(premasterSecret *big.Int, newHash func() hash.Hash) []byte {
	hash := newHash()
	hash.Write(premasterSecret.Bytes())
	return hash.Sum(nil)
}

func ExchangeMessage(login, salt, sessionKey []byte, g, N, clientPK, serverPK *big.Int, newHash func() hash.Hash) []byte {
	hash := newHash()
	hash.Write(g.Bytes())
	hashedG := hash.Sum(nil)
	hash = newHash()
	hash.Write(N.Bytes())
	hashedN := hash.Sum(nil)

	a := new(big.Int).SetBytes(hashedG)
	b := new(big.Int).SetBytes(hashedN)
	xor := new(big.Int).Xor(a, b)

	hash = newHash()
	hash.Write(login)
	hashedLogin := hash.Sum(nil)

	hash = newHash()
	hash.Write(xor.Bytes())
	hash.Write(hashedLogin)
	hash.Write(salt)
	hash.Write(clientPK.Bytes())
	hash.Write(serverPK.Bytes())
	hash.Write(sessionKey)

	return hash.Sum(nil)
}
