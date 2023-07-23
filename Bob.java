package rangeProof;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Bob {
    public Bob(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
    public boolean verify(String[] receive) {
        SHA256 sha256 = new SHA256();
        d_1 = 2100 - 2000;

        p = receive[0];
        sig_c = receive[1];

        String tmp = p;
        for (int i = 0; i < d_1; i++)
            tmp = sha256.hash(tmp);
        c = tmp;

        sig_cc = Sign_RSA.sign(privateKey, c);
        if (sig_c.equalsIgnoreCase(sig_cc)) return true;
        return false;
    }

    public int d_1;
    public String p, sig_c, sig_cc, c;
    private PrivateKey privateKey;
    public PublicKey publicKey;
}
