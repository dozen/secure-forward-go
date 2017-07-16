package main

import (
	"crypto/sha512"
	"encoding/hex"
	"crypto/rand"
)

const (
	SharedKeySaltLength = 16
)

/*
 * sha512_hex(sharedkey_salt + selfhostname + nonce + sharedkey)
 */
func SharedKeyDigest(sharedKeySalt, selfHostName, nonce, sharedKey []byte) []byte {
	dig := sha512.New()
	dig.Write(sharedKeySalt)
	dig.Write(selfHostName)
	dig.Write(nonce)
	dig.Write(sharedKey)
	digest := dig.Sum(nil)

	hexDigest := make([]byte, hex.EncodedLen(len(digest)))
	hex.Encode(hexDigest, digest)

	return hexDigest
}

/*
 * Generate shared_key_salt
 */
func SharedKeySalt() []byte {
	sharedKeySalt := make([]byte, SharedKeySaltLength)
	if _, err := rand.Read(sharedKeySalt); err != nil {
		panic("salt生成に失敗")
	}
	return sharedKeySalt
}
