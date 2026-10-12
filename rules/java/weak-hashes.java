// Test fixtures for pqc-semgrep-rules / Java / classically-broken hashes.
import java.security.MessageDigest;

public class WeakHashesFixture {
    public static void main(String[] args) throws Exception {
        // ruleid: pqc.java.md5
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        // ruleid: pqc.java.sha1
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        // ruleid: pqc.java.sha1
        MessageDigest sha1alt = MessageDigest.getInstance("SHA1");

        // ok: pqc.java.md5
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    }
}
