// Test fixtures for pqc-semgrep-rules / TypeScript / classically-broken hashes.
import * as crypto from "crypto";

function vulnerable(): void {
    // ---- MD5 ----
    // ruleid: pqc.javascript.md5
    const m1: string = crypto.createHash("md5").update("x").digest("hex");
    // ruleid: pqc.javascript.md5
    const m2: string = crypto.createHash("MD5").update("x").digest("hex");

    // ---- SHA-1 ----
    // ruleid: pqc.javascript.sha1
    const s1: string = crypto.createHash("sha1").update("y").digest("hex");
    // ruleid: pqc.javascript.sha1
    const s2: string = crypto.createHash("SHA1").update("y").digest("hex");
}

function safe(): void {
    // ok: pqc.javascript.md5
    const ok: string = crypto.createHash("sha256").update("safe").digest("hex");
}
