import oqs

# ruleid: pqc.python.ml-kem
kem = oqs.KeyEncapsulation("ML-KEM-768")
# ruleid: pqc.python.ml-dsa
signer = oqs.Signature("ML-DSA-65")
# ok: pqc.python.ml-dsa
legacy = oqs.Signature("Falcon-512")
