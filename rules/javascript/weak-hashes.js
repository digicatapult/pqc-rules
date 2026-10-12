// Test fixtures for pqc-semgrep-rules / JavaScript / classically-broken hashes.
const crypto = require('crypto');

function vulnerable() {
    // ---- MD5 ----
    // ruleid: pqc.javascript.md5
    crypto.createHash('md5').update('x').digest('hex');
    // ruleid: pqc.javascript.md5
    crypto.createHash('MD5').update('x').digest('hex');

    // ---- SHA-1 ----
    // ruleid: pqc.javascript.sha1
    crypto.createHash('sha1').update('y').digest('hex');
    // ruleid: pqc.javascript.sha1
    crypto.createHash('SHA1').update('y').digest('hex');
}

function safe() {
    // ok: pqc.javascript.md5
    crypto.createHash('sha256').update('safe').digest('hex');
}
