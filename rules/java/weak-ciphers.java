// Test fixtures for pqc-semgrep-rules / Java / classically-broken ciphers.
import javax.crypto.Cipher;

public class WeakCiphersFixture {
    public static void main(String[] args) throws Exception {
        // ruleid: pqc.java.des
        Cipher des1 = Cipher.getInstance("DES");
        // ruleid: pqc.java.des
        Cipher des2 = Cipher.getInstance("DES/CBC/PKCS5Padding");

        // ruleid: pqc.java.3des
        Cipher des3 = Cipher.getInstance("DESede");
        // ruleid: pqc.java.3des
        Cipher des4 = Cipher.getInstance("DESede/CBC/PKCS5Padding");

        // ruleid: pqc.java.rc4
        Cipher rc4_1 = Cipher.getInstance("RC4");
        // ruleid: pqc.java.rc4
        Cipher rc4_2 = Cipher.getInstance("ARCFOUR");

        // ok: pqc.java.des
        Cipher safe = Cipher.getInstance("AES/GCM/NoPadding");
    }
}
