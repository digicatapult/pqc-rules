// Test fixtures for pqc-semgrep-rules / JavaScript / Shor-broken cryptography.
const crypto = require('crypto');

function vulnerable() {
    // ---- RSA ----
    // ruleid: pqc.javascript.rsa
    crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    // ruleid: pqc.javascript.rsa
    crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, publicKey, privateKey) => {});

    // ---- EC ----
    // ruleid: pqc.javascript.ec
    crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    // ruleid: pqc.javascript.ec
    crypto.createECDH('secp256k1');

    // ---- DSA ----
    // ruleid: pqc.javascript.dsa
    crypto.generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 });

    // ---- DH ----
    // ruleid: pqc.javascript.dh
    crypto.createDiffieHellman(2048);
    // ruleid: pqc.javascript.dh
    crypto.getDiffieHellman('modp14');

    // ---- X25519 ----
    // ruleid: pqc.javascript.x25519
    crypto.generateKeyPairSync('x25519');

    // ---- Ed25519 ----
    // ruleid: pqc.javascript.ed25519
    crypto.generateKeyPairSync('ed25519');
}

function safe() {
    // ok: pqc.javascript.rsa
    crypto.randomBytes(32);
}
