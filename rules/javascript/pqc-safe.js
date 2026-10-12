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
