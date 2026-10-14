import java.security.*;
import java.util.Base64;

// Software Security (SDEV 4303) - Chapter 02
// RSA digital signature: generate keys, sign a message, verify the signature.
public class RSASignature {

    // Show the first n bytes of an array in hexadecimal
    static String hex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(String.format("%02x", b[i]));
        return sb.toString();
    }

    // Sign the message with the private key (SHA-256 hash + RSA)
    static byte[] sign(PrivateKey key, byte[] msg) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(msg);
        return s.sign();
    }

    // Verify the signature with the public key
    static boolean verify(PublicKey key, byte[] msg, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(key);
        s.update(msg);
        return s.verify(sig);
    }

    public static void main(String[] args) throws Exception {
        // Step 1: key generation
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        System.out.println("=== Step 1: Key generation (RSA-2048) ===");
        String pub = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(kp.getPublic().getEncoded());
        System.out.println("-----BEGIN PUBLIC KEY-----\n" + pub + "\n-----END PUBLIC KEY-----");

        // Step 2: signing
        byte[] message = "Transfer $1000 to Mark".getBytes("UTF-8");
        byte[] sig = sign(kp.getPrivate(), message);
        System.out.println("\n=== Step 2: Signing ===");
        System.out.println("Message   : " + new String(message, "UTF-8"));
        System.out.println("Signature : " + hex(sig, 32) + "... (" + sig.length + " bytes)");

        // Step 3: verification (original message, then a changed message)
        System.out.println("\n=== Step 3: Verification ===");
        System.out.println("Original message  -> "
                + (verify(kp.getPublic(), message, sig) ? "VALID" : "INVALID"));
        byte[] tampered = "Transfer $1000 to Oscar".getBytes("UTF-8");
        System.out.println("Tampered message  -> "
                + (verify(kp.getPublic(), tampered, sig) ? "VALID" : "INVALID"));
    }
}
