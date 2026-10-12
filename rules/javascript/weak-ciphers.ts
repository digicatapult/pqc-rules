// Test fixtures for pqc-semgrep-rules / TypeScript / classically-broken ciphers.
import * as crypto from "crypto";

function vulnerable(): void {
    // ruleid: pqc.javascript.des
    const c1: crypto.Cipher = crypto.createCipheriv("des-cbc", Buffer.alloc(8), Buffer.alloc(8));

    // ruleid: pqc.javascript.3des
    const c2: crypto.Cipher = crypto.createCipheriv(
        "des-ede3-cbc",
        Buffer.alloc(24),
        Buffer.alloc(8),
    );

    // ruleid: pqc.javascript.rc4
    const c3: crypto.Cipher = crypto.createCipheriv("rc4", Buffer.alloc(16), null);
}

function safe(): void {
    // ok: pqc.javascript.des
    const ok: crypto.CipherGCM = crypto.createCipheriv(
        "aes-256-gcm",
        Buffer.alloc(32),
        Buffer.alloc(12),
    ) as crypto.CipherGCM;
}
