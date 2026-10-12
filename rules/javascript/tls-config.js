const https = require("https");
const tls = require("tls");
// ruleid: pqc.javascript.tls-legacy-version
https.createServer({ key, cert, minVersion: "TLSv1" }, app);
// ruleid: pqc.javascript.tls-legacy-version
tls.connect({ host, port, secureProtocol: "TLSv1_1_method" });
// ok: pqc.javascript.tls-legacy-version
https.createServer({ key, cert, minVersion: "TLSv1.3" }, app);
// ruleid: pqc.javascript.tls-classical-groups
tls.createServer({ key, cert, ecdhCurve: "P-256:X25519" });
// ruleid: pqc.javascript.tls-hybrid-groups
tls.createServer({ key, cert, ecdhCurve: "X25519MLKEM768:X25519" });
