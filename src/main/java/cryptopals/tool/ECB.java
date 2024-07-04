package cryptopals.tool;

import static cryptopals.utils.PKCS7Util.applyPadding;
import static cryptopals.utils.PKCS7Util.stripPadding;

import cryptopals.enums.CipherMode;
import cryptopals.exceptions.ECBException;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

/**
 * A tool for ECB-related operations
 */
public class ECB {

    private static final String AES = "AES";

    private final byte[] cipherKeyBytes;

    public ECB(byte[] cipherKeyBytes) {
        this.cipherKeyBytes = cipherKeyBytes;
    }

    /**
     * Decrypt a message in AES-ECB 128 bit mode
     *
     * this is the solution to challenge 7
     * @param cipherTextBytes bytes of the cipher text string
     * @param cipherMode one of the public static ints attached to {@link Cipher}
     * @return a byte array of the decrypted bytes
     * @throws ECBException if a problem with the operation surfaces
     */
    public byte[] AES128(byte[] cipherTextBytes, CipherMode cipherMode) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");;
            Key cipherKey = new SecretKeySpec(cipherKeyBytes, AES);
            cipher.init(cipherMode.getIntValue(), cipherKey);
            return cipher.doFinal(cipherTextBytes);
        } catch (Exception e) {
            throw new ECBException(String.format("Could not perform %s operation", cipherMode), e);
        }
    }

    public byte[] AES128WPadding(byte[] cipherTextBytes, CipherMode cipherMode) {
        //implement padding
        if (cipherMode == CipherMode.ENCRYPT) {
            cipherTextBytes = applyPadding(cipherTextBytes, cipherKeyBytes.length);
        }

        var theFinal = AES128(cipherTextBytes, cipherMode);

        if (cipherMode == CipherMode.DECRYPT) {
            theFinal = stripPadding(theFinal);
        }

        return theFinal;
    }
}
