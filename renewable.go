package gogsrp

import (
	"crypto/sha1"
	"hash"
)

type RenewableHash interface {
	New() hash.Hash
}

type RenewableSHA1 struct{}

func (RenewableSHA1) New() hash.Hash {
	return sha1.New()
}
