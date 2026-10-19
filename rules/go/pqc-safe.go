package main

import (
        "crypto/mlkem"

        "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func keys() {
        // ruleid: pqc.go.ml-kem
        dk, _ := mlkem.GenerateKey768()
        _ = dk
        // ruleid: pqc.go.ml-dsa
        pk, sk, _ := mldsa65.GenerateKey(nil)
        _, _ = pk, sk
}
