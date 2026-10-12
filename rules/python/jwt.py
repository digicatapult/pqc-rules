import jwt

# ruleid: pqc.python.jwt-rsa
jwt.encode({"sub": "1"}, private_key, algorithm="RS256")
# ruleid: pqc.python.jwt-rsa
jwt.encode({"sub": "1"}, private_key, algorithm="PS512", headers={"kid": "k"})
# ruleid: pqc.python.jwt-ecc
jwt.encode({"sub": "1"}, private_key, algorithm="ES256")
# ok: pqc.python.jwt-rsa
jwt.encode({"sub": "1"}, secret, algorithm="HS512")
