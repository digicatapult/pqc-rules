package main

import (
        "crypto/aes"
        "crypto/des"
        "crypto/rc4"
)

func vulnerableCiphers() {
        // ruleid: pqc.go.des
        _, _ = des.NewCipher(make([]byte, 8))

        // ruleid: pqc.go.3des
        _, _ = des.NewTripleDESCipher(make([]byte, 24))

        // ruleid: pqc.go.rc4
        _, _ = rc4.NewCipher(make([]byte, 16))
}

func safeCiphers() {
        // ok: pqc.go.des
        _, _ = aes.NewCipher(make([]byte, 32))
}
