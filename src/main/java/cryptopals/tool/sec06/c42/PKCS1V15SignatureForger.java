package cryptopals.tool.sec06.c42;

import cryptopals.tool.sec05.RSA;
import lombok.experimental.UtilityClass;

/**
 * This is an RSA Signature verifier. It validates RSA Signatures.
 * It's also extremely flawed. It doesn't validate right justification
 * of the message
 */
@UtilityClass
public class PKCS1V15SignatureForger {

    /**
     * force a signature that takes advantage of bleichenbacher's RSA signature forgery exploit
     * this exploit requires a public lock of e=3.
     *
     * @param message
     * @return
     */
    public String forgeASignature(final String message) {
        final var keypair = RSA.keyGen(1024, 3);
        //TODO: implement me
        return null;
    }
}
