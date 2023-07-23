package rangeProof;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Alice {
    public Alice(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public String[] calProof(String[] receive) {
        SHA256 sha256 = new SHA256();

        s = receive[0];
        sig_c = receive[1];

        d_0 = 2000 - 1978;
        String tmp = s;
        for (int i = 0; i < d_0; i++)
            tmp = sha256.hash(tmp);
        p = tmp;

        return new String[]{p, sig_c};
    }

    public int d_0;
    public String p, c;
    public String s, sig_c;
    private PrivateKey privateKey;
    public PublicKey publicKey;
}
