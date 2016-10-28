package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
)

func gen(n, prob int) (*big.Int, *big.Int, *big.Int) {
	for {
		q, err := rand.Prime(rand.Reader, n-1)
		if err != nil {
			panic(err.Error())
		}
		n := new(big.Int).Mul(q, big.NewInt(2))
		p := new(big.Int).Add(n, big.NewInt(1))
		// p = 2q + 1, order(p) = n = 2q
		if p.ProbablyPrime(prob) {
			for {
				a, err := rand.Int(rand.Reader, p)
				if err != nil {
					panic(err.Error())
				}
				if b := new(big.Int).Exp(a, big.NewInt(2), p); b.Cmp(big.NewInt(1)) == 0 {
					continue
				}
				if b := new(big.Int).Exp(a, q, p); b.Cmp(big.NewInt(1)) == 0 {
					return p, q, a
				}
			}
		}
	}
	return nil, nil, nil
}

var mutex = &sync.Mutex{}

func printPrimes(n, prob int) {
	fmt.Println("start...")
	p, q, g := gen(n, prob)
	mutex.Lock()
	fmt.Println("p = ", p)
	fmt.Println("q = ", q)
	fmt.Println("g = ", g)
	mutex.Unlock()
}

func main() {

	result := make(chan *big.Int)
	threads := 4

	for i := 0; i < threads; i++ {
		go func() {
			p, q, g := gen(1024, 64)
			mutex.Lock()
			result <- p
			result <- q
			result <- g
			mutex.Unlock()
		}()
	}
	for i := 0; i < threads; i++ {
		fmt.Println("p = ", <-result)
		fmt.Println("q = ", <-result)
		fmt.Println("g = ", <-result)
	}
}
