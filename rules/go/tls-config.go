package main

import "crypto/tls"

func configs() {
        // ruleid: pqc.go.tls-legacy-version
        _ = &tls.Config{MinVersion: tls.VersionTLS10}
        // ok: pqc.go.tls-legacy-version
        _ = &tls.Config{MinVersion: tls.VersionTLS13}
        // ruleid: pqc.go.tls-classical-groups
        _ = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}
        _ = &tls.Config{
                // ruleid: pqc.go.tls-hybrid-groups
                CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
        }
}
