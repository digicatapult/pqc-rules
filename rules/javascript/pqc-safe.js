const { ml_kem768 } = require("@noble/post-quantum/ml-kem");
const { ml_dsa65 } = require("@noble/post-quantum/ml-dsa");
const crypto = require("crypto");
// ruleid: pqc.javascript.ml-kem
const kp = ml_kem768.keygen();
// ruleid: pqc.javascript.ml-kem
const { cipherText, sharedSecret } = ml_kem768.encapsulate(kp.publicKey);
// ruleid: pqc.javascript.ml-dsa
const sig = ml_dsa65.sign(secretKey, msg);
// ruleid: pqc.javascript.ml-kem
const nk = crypto.generateKeyPairSync("ml-kem-768");
// ruleid: pqc.javascript.ml-dsa
const nd = crypto.generateKeyPairSync("ml-dsa-65");
// ok: pqc.javascript.ml-kem
const rk = crypto.generateKeyPairSync("ed448");
// ruleid: pqc.javascript.ml-kem
const ss = ml_kem768.decapsulate(cipherText, kp.secretKey);
// ruleid: pqc.javascript.ml-dsa
const ok = ml_dsa65.verify(publicKey, msg, sig);

const { generateKeyPairSync } = require("node:crypto");
// ruleid: pqc.javascript.ml-kem
const nk2 = generateKeyPairSync("ML-KEM-1024");
// ruleid: pqc.javascript.ml-dsa
const nd2 = generateKeyPairSync("slh-dsa-sha2-128s");

// Node's crypto.encapsulate() uses whichever KEM the key's type implies (RSA, EC,
// X25519/X448 or ML-KEM), so the call alone does not show that ML-KEM is in use.
// ok: pqc.javascript.ml-kem
const enc = crypto.encapsulate(publicKey);

// Comments and strings are not usage, e.g. ml_kem768.keygen() or ml_dsa65.sign(sk, m).
// ok: pqc.javascript.ml-kem
const note = "call ml_kem768.keygen() to create a key";
// ok: pqc.javascript.ml-dsa
const doc = "ml_dsa65.sign(secretKey, msg)";
