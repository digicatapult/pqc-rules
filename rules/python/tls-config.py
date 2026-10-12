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
