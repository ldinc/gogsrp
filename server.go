package gogsrp

import (
	"hash"
	"math/big"
)

type Server struct {
	g            *big.Int
	N            *big.Int
	randomLength int
	saltLen      uint
	keyLen       uint
	newHash      func() hash.Hash
}

func CreateServer(g, N *big.Int, randomLength int, newHash func() hash.Hash) *Server {
	server := new(Server)
	server.g = g
	server.N = N
	server.newHash = newHash
	server.randomLength = randomLength
	server.saltLen = 32
	server.keyLen = 32

	return server
}

func (server *Server) NewSalt() ([]byte, error) {
	return RandomBytes(server.saltLen)
}

func (server *Server) NewPrivateKey() (*big.Int, error) {
	rnd, err := RandomBytes(server.keyLen)
	if err != nil {
		return nil, err
	}
	sk := new(big.Int)
	sk = sk.SetBytes(rnd)

	return sk, nil
}

func (server *Server) NewPublicKey(sk, verifier *big.Int) (*big.Int, error) {
	hash := server.newHash()
	hash.Write(server.N.Bytes())
	//TODO pad(g)
	hash.Write(Pad(server.g.Bytes(), len(server.N.Bytes())))
	k := new(big.Int)
	k = k.SetBytes(hash.Sum(nil))
	y := new(big.Int)
	y = y.Exp(server.g, sk, server.N)
	x := new(big.Int)
	x = x.Mul(k, verifier)
	pk := new(big.Int)
	pk = pk.Add(x, y)
	//TODO rem(pk, N)
	pk = pk.Rem(pk, server.N)
	return pk, nil
}

func (server *Server) GetPremasterSecret(clientPK, serverPK, serverSK, verifier *big.Int) *big.Int {
	u, _ := CommonHash(clientPK, serverPK, server.newHash)
	y := new(big.Int)
	y = y.Exp(verifier, u, server.N)
	x := new(big.Int)
	x = x.Mul(clientPK, y)
	secret := new(big.Int)
	secret = secret.Exp(x, serverSK, server.N)
	return secret
}
