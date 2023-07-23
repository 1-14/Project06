package rangeProof;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class Issuer {
    public Issuer(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
    public String[] setup() {
        SHA256 sha256 = new SHA256();

        seed = genRandom();
        s = sha256.hash(seed);
        k = 2100 - 1978;

        c = s;
        for (int i = 0; i < k; i++)
            c = sha256.hash(c);
        sig_c = Sign_RSA.sign(privateKey, c);

        return new String[]{s, sig_c};
    }

    private String genRandom() {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[16];

        random.nextBytes(randomBytes);

        StringBuilder sb = new StringBuilder();
        for (byte b : randomBytes)
            sb.append(String.format("%02x", b));

        return sb.toString();
    }

    public int k;
    public String seed, c, s, sig_c;
    private PrivateKey privateKey;
    public PublicKey publicKey;
}
