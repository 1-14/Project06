package rangeProof;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class Sign_RSA {
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static String sign(PrivateKey privateKey, String data) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);

            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            signature.update(dataBytes);

            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean verify(PublicKey publicKey, String data, String signature) {
        try {
            Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifier.initVerify(publicKey);

            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            verifier.update(dataBytes);

            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return verifier.verify(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
