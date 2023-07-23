import rangeProof.*;

import java.security.*;

public class Main {
    public static void main(String[] args) {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }
        Issuer issuer = new Issuer(privateKey, publicKey);
        Alice alice = new Alice(privateKey, publicKey);
        Bob bob = new Bob(privateKey, publicKey);

        String[] tmp1 = issuer.setup();
        String[] tmp2 = alice.calProof(tmp1);
        boolean res = bob.verify(tmp2);

        if (res) System.out.println("验证成功");
        else System.out.println("验证失败");

    }
}