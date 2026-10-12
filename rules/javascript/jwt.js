const jwt = require("jsonwebtoken");
const jose = require("jose");

// ruleid: pqc.javascript.jwt-rsa
jwt.sign({ sub: "1" }, privateKey, { algorithm: "RS256" });
// ruleid: pqc.javascript.jwt-rsa
jwt.sign({ sub: "1" }, privateKey, { expiresIn: "1h", algorithm: 'PS384' });
// ruleid: pqc.javascript.jwt-ecc
jwt.sign({ sub: "1" }, privateKey, { algorithm: "ES256" });
// ok: pqc.javascript.jwt-rsa
jwt.sign({ sub: "1" }, secret, { algorithm: "HS512" });

async function f() {
  // ruleid: pqc.javascript.jwt-rsa
  await jose.generateKeyPair("RS256");
  // ruleid: pqc.javascript.jwt-ecc
  await jose.generateKeyPair("EdDSA");
  // ruleid: pqc.javascript.jwt-ecc
  await new jose.SignJWT({}).setProtectedHeader({ alg: "ES384" }).sign(k);
  // ok: pqc.javascript.jwt-ecc
  await new jose.SignJWT({}).setProtectedHeader({ alg: "HS256" }).sign(k);
}
