// Test fixtures for pqc-semgrep-rules / TypeScript / Shor-broken cryptography.
// Same patterns as shor-broken.js but with TypeScript-specific syntax
// (explicit types, `as` casts) to verify the rules match through the TS
// parser path as well.

import * as crypto from "crypto";

function vulnerable(): void {
    // ---- RSA ----
    // ruleid: pqc.javascript.rsa
    const rsa1 = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    // ruleid: pqc.javascript.rsa
    crypto.generateKeyPair(
        "rsa",
        { modulusLength: 2048 },
        (err: Error | null, publicKey: crypto.KeyObject, privateKey: crypto.KeyObject) => {},
    );

    // ---- EC ----
    // ruleid: pqc.javascript.ec
    const ec1 = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    // ruleid: pqc.javascript.ec
    const ecdh: crypto.ECDH = crypto.createECDH("secp256k1");

    // ---- DSA ----
    // ruleid: pqc.javascript.dsa
    const dsa1 = crypto.generateKeyPairSync("dsa", {
        modulusLength: 2048,
        divisorLength: 256,
    });

    // ---- DH ----
    // ruleid: pqc.javascript.dh
    const dh1: crypto.DiffieHellman = crypto.createDiffieHellman(2048);
    // ruleid: pqc.javascript.dh
    const dh2 = crypto.getDiffieHellman("modp14");

    // ---- X25519 ----
    // ruleid: pqc.javascript.x25519
    const x = crypto.generateKeyPairSync("x25519");

    // ---- Ed25519 ----
    // ruleid: pqc.javascript.ed25519
    const ed = crypto.generateKeyPairSync("ed25519");
}

function safe(): void {
    // ok: pqc.javascript.rsa
    const buf: Buffer = crypto.randomBytes(32);
}
