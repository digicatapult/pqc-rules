async function f() {
  // ruleid: pqc.javascript.webcrypto-rsa
  await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: e, hash: "SHA-256" }, true, ["encrypt"]);
  // ruleid: pqc.javascript.webcrypto-rsa
  await window.crypto.subtle.importKey("spki", der, { name: "RSA-PSS", hash: "SHA-256" }, true, ["verify"]);
  // ruleid: pqc.javascript.webcrypto-ecc
  await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  // ruleid: pqc.javascript.webcrypto-ecc
  await subtle.generateKey("Ed25519", true, ["sign"]);
  // ok: pqc.javascript.webcrypto-rsa
  await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  // ok: pqc.javascript.webcrypto-ecc
  await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-512" }, true, ["sign"]);
}
