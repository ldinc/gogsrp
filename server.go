package gogsrp

import (
	"fmt"
	"math/big"
)

type Server struct {
	g            *big.Int
	N            *big.Int
	randomLength int
	hash         RenewableHash
}

func CreateServer(g, N *big.Int, randomLength int, hash RenewableHash) *Server {
	server := new(Server)
	server.g = g
	server.N = N
	server.hash = hash
	server.randomLength = randomLength

	return server
}

// k = H(N | pad(g))
// TODO: pad(g) to 256 bit
func (server *Server) CreatePremasterSecret(verifier, clientPub *big.Int) *big.Int {
	rnd, err := ReadRand(server.randomLength)
	if err != nil {

	}
	serverPriv := new(big.Int)
	serverPriv = serverPriv.SetBytes(rnd)
	khash := server.hash.New()
	khash.Write(server.N.Bytes())
	khash.Write(server.g.Bytes())
	hash := khash.Sum(nil)
	k := new(big.Int)
	k = k.SetBytes(hash)
	fmt.Println("k = ", k)
	t := new(big.Int)
	t = t.Exp(server.g, serverPriv, server.N)
	z := new(big.Int)
	z = z.Mul(k, verifier)
	serverPub := new(big.Int)
	serverPub = serverPub.Add(z, t)
	fmt.Println("server public key = ", serverPub)
	// u = H(pad(A) | pad(b))
	uhash := server.hash.New()
	uhash.Write(clientPub.Bytes())
	uhash.Write(serverPub.Bytes())
	ubytes := uhash.Sum(nil)
	u := new(big.Int)
	u = u.SetBytes(ubytes)
	t = t.Exp(verifier, u, server.N)
	z = z.Mul(clientPub, t)
	premasterSecret := new(big.Int)
	premasterSecret = premasterSecret.Exp(z, serverPriv, server.N)
	fmt.Println("server premaster secret = ", premasterSecret)
	return serverPub
}
