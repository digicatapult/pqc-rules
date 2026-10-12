const forge = require("node-forge");
// ruleid: pqc.javascript.forge-rsa
const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
// ruleid: pqc.javascript.forge-rsa
const priv = forge.pki.privateKeyFromPem(pem);
// ruleid: pqc.javascript.forge-md5
const h1 = forge.md.md5.create();
// ruleid: pqc.javascript.forge-sha1
const h2 = forge.md.sha1.create();
// ok: pqc.javascript.forge-md5
const h3 = forge.md.sha512.create();
