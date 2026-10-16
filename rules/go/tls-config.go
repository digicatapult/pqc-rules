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

        // nil means Go's defaults, which put X25519MLKEM768 first.
        // ok: pqc.go.tls-classical-groups
        _ = &tls.Config{CurvePreferences: nil}

        // A variable holding the hybrid list is reported once, where the list is built.
        // ruleid: pqc.go.tls-hybrid-groups
        hybrid := []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
        // ok: pqc.go.tls-classical-groups
        _ = &tls.Config{CurvePreferences: hybrid}
        // ok: pqc.go.tls-classical-groups
        _ = &tls.Config{CurvePreferences: preferredCurves()}

        // ruleid: pqc.go.tls-hybrid-groups
        _ = &tls.Config{CurvePreferences: []tls.CurveID{tls.SecP256r1MLKEM768, tls.CurveP256}}
        // ruleid: pqc.go.tls-hybrid-groups
        _ = &tls.Config{CurvePreferences: []tls.CurveID{tls.SecP384r1MLKEM1024}}

        cfg := &tls.Config{}
        // ruleid: pqc.go.tls-legacy-version
        cfg.MinVersion = tls.VersionTLS11
        // ruleid: pqc.go.tls-legacy-version
        _ = &tls.Config{MinVersion: tls.VersionSSL30}
        // ok: pqc.go.tls-legacy-version
        cfg.MinVersion = tls.VersionTLS12
}
