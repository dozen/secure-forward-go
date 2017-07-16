package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/ugorji/go/codec"
	"fmt"
	"net"
	"time"
	"strings"
	"math/rand"
)

const (
	HELO = "HELO"
	PING = "PING"
	PONG = "PONG"
	rootPEM = `-----BEGIN CERTIFICATE-----
MIIDIDCCAggCAQEwDQYJKoZIhvcNAQELBQAwTTELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAkNBMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRkwFwYDVQQDDBBTZWN1cmVG
b3J3YXJkIENBMB4XDTcwMDEwMTAwMDAwMFoXDTIyMDcwMTEyMjIwNVowTTELMAkG
A1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRkw
FwYDVQQDDBBTZWN1cmVGb3J3YXJkIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAohm6OFwZZz9aVWuFMhpsFYIyDw+woEjpaoWD9BCvy/uE9GXtUHN9
JWPTQfJROxOTSmwQ5UqvVypLQ948QXQTSpz45ksyqmowWPK3+LBAXK/W7yKQN6gx
oho4Mhv8gH2w1m8MuNefsw0EQgyCm0otgyT2PxGyEA+6z9ObRqjZHu5HGbSfXSGw
cM799aI6UmOHHFRvf75HMKfr6PQJNB238WmO+RkOc9VbnK1nZsjFTWfJ7sHZsy4s
8q2ves6/CeLWoTKSqdcG7/TAgPu5MSnqnXjvW2drjkByEnap73eQYDC8rvzIoORJ
j1gr9t+gRPXyyvW9LswbsV3xKyBEPUb9vwIDAQABoxAwDjAMBgNVHRMEBTADAQH/
MA0GCSqGSIb3DQEBCwUAA4IBAQCMeOqPlM7W3Gwki6J33bQfw4GT0lrICPBY/Q+R
YHwmT7BMlbBGcuHvijujnhXHoSHrOvElwd1Xf9qUselVD8E9ZxTZtd87ypLWiT02
28R/80QVwj6HytPZezwDik/+MegEHG3e5JwOlXDSEwDEJQZzQrGX2aGWOJlc0I4z
zuR4EhSNb20zmiEGEVUw0qP6C6+a7Begc25v03Py5+djAPv3hyEQGosfn9BmqAye
5mBlp/zeP+YfQi5vsv8L752HvYxPI3IVADx6+KOmWwxnz6PIo+zxv0Jb7u+0dlNa
6JNNwMLFBjLRhzj9baZnc42ZhcQAFr1sMCwfIVL95dC1cO2B
-----END CERTIFICATE-----`
)

type First struct {
	METHOD []byte
	selfHostName []byte
	sharedKeySalt []byte
	Option map [string]interface{}
}

var Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func main() {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}

	server := "ubuntu.lan:24284"

	host, port, err := net.SplitHostPort(server)
	if err != nil {
		panic(err)
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		panic(err)
	}
	// for DNS round robin
	n := Rand.Intn(len(addrs))
	addr := addrs[n]
	var format string
	if strings.Contains(addr, ":") {
		// v6
		format = "[%s]:%s"
	} else {
		// v4
		format = "%s:%s"
	}
	resolved := fmt.Sprintf(format, addr, port)
	fmt.Println(resolved)

	conn, err := net.DialTimeout("tcp", resolved, time.Second * 10)
	if err != nil {
		panic(err)
	}
	conn = tls.Client(conn, &tls.Config{
		ServerName: host,
		RootCAs: roots,
	})

	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	var v First
	var mh codec.MsgpackHandle
	dec := codec.NewDecoder(conn, &mh)
	enc := codec.NewEncoder(conn, &mh)
	_ = enc

	if err := dec.Decode(&v); err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", v)

	sharedKeySalt := SharedKeySalt()
	sharedKey := []byte("test")
	selfHostName := []byte("mbp.lan")
	nonce := []byte(v.Option["nonce"].([]uint8))

	pingMsg := [][]byte{
		[]byte(PING),
		selfHostName,
		sharedKeySalt,
		SharedKeyDigest(sharedKeySalt, selfHostName, nonce, sharedKey),
		{},
		{},
	}

	if err := enc.Encode(pingMsg); err != nil {
		fmt.Printf("%#v\n", err)
	}

	var pingResult []interface{}
	if err := dec.Decode(&pingResult); err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", string(pingResult[0].([]byte)))
	fmt.Printf("%#v\n", pingResult[1])
	fmt.Printf("%#v\n", string(pingResult[2].([]byte)))

	conn.Close()
}