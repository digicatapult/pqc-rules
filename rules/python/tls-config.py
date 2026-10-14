import ssl

ctx = ssl.create_default_context()
# ruleid: pqc.python.tls-legacy-version
ctx.minimum_version = ssl.TLSVersion.TLSv1
# ruleid: pqc.python.tls-legacy-version
legacy = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
# ok: pqc.python.tls-legacy-version
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
# ruleid: pqc.python.tls-classical-groups
ctx.set_ecdh_curve("prime256v1")
# ruleid: pqc.python.tls-legacy-version
sock = ssl.wrap_socket(raw, ssl_version=ssl.PROTOCOL_TLSv1_1)

from OpenSSL import SSL

# ruleid: pqc.python.tls-legacy-version
pyopenssl_legacy = SSL.Context(SSL.TLSv1_METHOD)
# TLS_METHOD negotiates the highest version both sides support, so it is not legacy-only.
# ok: pqc.python.tls-legacy-version
pyopenssl_any = SSL.Context(SSL.TLS_METHOD)
