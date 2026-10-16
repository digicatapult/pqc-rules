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
// "auto" is Node's default and lets OpenSSL choose; with OpenSSL 3.5 that is X25519MLKEM768.
// ok: pqc.javascript.tls-classical-groups
tls.createServer({ key, cert, ecdhCurve: "auto" });
// Group names are case-insensitive in OpenSSL; tls-classical-groups must not fire here either.
// ruleid: pqc.javascript.tls-hybrid-groups
tls.createServer({ key, cert, ecdhCurve: "x25519mlkem768:x25519" });
// ruleid: pqc.javascript.tls-hybrid-groups
tls.createServer({ key, cert, ecdhCurve: "SecP256r1MLKEM768" });
// ok: pqc.javascript.tls-hybrid-groups
tls.createServer({ key, cert, ecdhCurve: "auto" });
// ruleid: pqc.javascript.tls-legacy-version
tls.connect({ host, port, secureProtocol: "TLSv1_method" });
