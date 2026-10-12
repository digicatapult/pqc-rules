// Test fixtures for pqc-semgrep-rules / JavaScript / classically-broken ciphers.
const crypto = require('crypto');

function vulnerable() {
    // ruleid: pqc.javascript.des
    crypto.createCipheriv('des-cbc', Buffer.alloc(8), Buffer.alloc(8));

    // ruleid: pqc.javascript.3des
    crypto.createCipheriv('des-ede3-cbc', Buffer.alloc(24), Buffer.alloc(8));

    // ruleid: pqc.javascript.rc4
    crypto.createCipheriv('rc4', Buffer.alloc(16), null);
}

function safe() {
    // ok: pqc.javascript.des
    crypto.createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12));
}
