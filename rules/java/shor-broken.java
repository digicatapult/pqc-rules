// Test fixtures for pqc-semgrep-rules / Java / Shor-broken cryptography.
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.KeyAgreement;

public class ShorBrokenFixture {
    public static void main(String[] args) throws Exception {
        // ---- RSA ----
        // ruleid: pqc.java.rsa
        KeyPairGenerator rsa1 = KeyPairGenerator.getInstance("RSA");
        // ruleid: pqc.java.rsa
        Signature rsaSig = Signature.getInstance("SHA256withRSA");

        // ---- EC ----
        // ruleid: pqc.java.ec
        KeyPairGenerator ec1 = KeyPairGenerator.getInstance("EC");
        // ruleid: pqc.java.ec
        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
        // ruleid: pqc.java.ec
        Signature ecSig = Signature.getInstance("SHA256withECDSA");

        // ---- DSA ----
        // ruleid: pqc.java.dsa
        KeyPairGenerator dsa1 = KeyPairGenerator.getInstance("DSA");
        // ruleid: pqc.java.dsa
        Signature dsaSig = Signature.getInstance("SHA256withDSA");

        // ---- DH ----
        // ruleid: pqc.java.dh
        KeyPairGenerator dh1 = KeyPairGenerator.getInstance("DiffieHellman");
        // ruleid: pqc.java.dh
        KeyAgreement dhKa = KeyAgreement.getInstance("DH");

        // Safe (should NOT match these rules)
        // ok: pqc.java.rsa
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    }
}
