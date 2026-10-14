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

const { generateKeyPairSync, generateKeyPair, createECDH, getDiffieHellman } = require("node:crypto");
const nc = require("node:crypto");

function aliased() {
    // ruleid: pqc.javascript.rsa
    generateKeyPairSync("rsa", { modulusLength: 2048 });
    // ruleid: pqc.javascript.rsa
    nc.generateKeyPairSync("RSA", { modulusLength: 2048 });
    // ruleid: pqc.javascript.rsa
    generateKeyPair("rsa-pss", { modulusLength: 2048 }, () => {});
    // ruleid: pqc.javascript.ec
    nc.generateKeyPairSync("EC", { namedCurve: "P-256" });
    // ruleid: pqc.javascript.ec
    createECDH("prime256v1");
    // ruleid: pqc.javascript.dsa
    nc.generateKeyPairSync("dsa", { modulusLength: 2048 });
    // ruleid: pqc.javascript.dh
    getDiffieHellman("modp14");
    // ruleid: pqc.javascript.x25519
    generateKeyPairSync("x25519");
    // ruleid: pqc.javascript.ed25519
    nc.generateKeyPairSync("ed25519");
    // ok: pqc.javascript.rsa
    generateKeyPairSync("ml-dsa-65");
}
