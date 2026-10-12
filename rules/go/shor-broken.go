package main

import (
        "crypto/dsa"
        "crypto/ecdh"
        "crypto/ecdsa"
        "crypto/ed25519"
        "crypto/elliptic"
        "crypto/rand"
        "crypto/rsa"
)

func vulnerable() {
        // ruleid: pqc.go.rsa
        _, _ = rsa.GenerateKey(rand.Reader, 2048)

        // ruleid: pqc.go.ecdsa
        _, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

        // ruleid: pqc.go.ecdh
        _, _ = ecdh.P256().GenerateKey(rand.Reader)

        var params dsa.Parameters
        // ruleid: pqc.go.dsa
        _ = dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N224)

        // ruleid: pqc.go.x25519
        _, _ = ecdh.X25519().GenerateKey(rand.Reader)

        // ruleid: pqc.go.ed25519
        _, _, _ = ed25519.GenerateKey(rand.Reader)
}
