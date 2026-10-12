package main

import (
        "crypto/md5"
        "crypto/sha1"
        "crypto/sha256"
)

func vulnerableHashes() {
        // ruleid: pqc.go.md5
        _ = md5.New()
        // ruleid: pqc.go.md5
        _ = md5.Sum([]byte("x"))

        // ruleid: pqc.go.sha1
        _ = sha1.New()
        // ruleid: pqc.go.sha1
        _ = sha1.Sum([]byte("y"))
}

func safeHashes() {
        // ok: pqc.go.md5
        _ = sha256.New()
}
