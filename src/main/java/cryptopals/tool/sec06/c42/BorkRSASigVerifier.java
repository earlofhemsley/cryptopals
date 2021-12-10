package cryptopals.tool.sec06.c42;

import cryptopals.exceptions.BadPaddingRuntimeException;
import cryptopals.tool.sec05.RSA;
import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.math.BigInteger;

/**
 * This is an RSA Signature verifier. It validates RSA Signatures.
 * It's also extremely flawed. It doesn't validate right justification
 * of the message
 */
@UtilityClass
public class BorkRSASigVerifier {

    public boolean signatureIsValid(final byte[] signature, final RSA.Key lock, final String expectedMessage) {
        final BigInteger sigAsBigInt = new BigInteger(1, signature);
        final byte[] modPowd = sigAsBigInt.modPow(lock.getK(), lock.getN()).toByteArray();

        final int asnStart = PKCS1V15RsaSignatureUtil.findAsnStartingIndex(modPowd);
        if (asnStart < 0) {
            throw new BadPaddingRuntimeException("Invalid PKCS1.5 Padding");
        }

        //need to interpret the ASN to get to the hash

        //need to hash the expected message

        //need to assert hash equality

        return false;
    }
}
