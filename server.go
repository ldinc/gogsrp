package gogsrp

import (
	"hash"
	"math/big"
)

type Server struct {
	g       *big.Int
	N       *big.Int
	saltLen int
	keyLen  int
	newHash func() hash.Hash
}

func CreateServer(g, N *big.Int, saltLen, keyLen int, newHash func() hash.Hash) *Server {
	server := new(Server)
	server.g = g
	server.N = N
	server.newHash = newHash
	server.saltLen = saltLen
	server.keyLen = keyLen

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
	sk := new(big.Int).SetBytes(rnd)

	return sk, nil
}

func (server *Server) NewPublicKey(sk, verifier *big.Int) (*big.Int, error) {
	Nbytes := server.N.Bytes()
	gbytes := server.g.Bytes()
	hash := server.newHash()
	hash.Write(Nbytes)
	hash.Write(Pad(gbytes, len(Nbytes)))
	k := new(big.Int).SetBytes(hash.Sum(nil))
	y := new(big.Int).Exp(server.g, sk, server.N)
	x := new(big.Int).Mul(k, verifier)
	pk := new(big.Int).Add(x, y)
	pk = pk.Rem(pk, server.N)
	return pk, nil
}

func (server *Server) GetPremasterSecret(clientPK, serverPK, serverSK, verifier *big.Int) *big.Int {
	u, _ := CommonHash(clientPK, serverPK, server.newHash)
	y := new(big.Int).Exp(verifier, u, server.N)
	x := new(big.Int).Mul(clientPK, y)
	secret := new(big.Int).Exp(x, serverSK, server.N)
	return secret
}
