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

    private final byte[] cipherKeyBytes;

    public ECB(byte[] cipherKeyBytes) {
        this.cipherKeyBytes = cipherKeyBytes;
    }

    /**
     * given a series of messages, detect which of the messages was decrypted in ECB mode.
     *
     * this is the solution to challenge eight
     * @param cipherBytes
     * @return true if found, false otherwise
     * @throws ECBException if a problem with ECB operation surfaces
     */
    public boolean detectInCipherBytes(byte[] cipherBytes) throws ECBException {
        if (cipherBytes.length % cipherKeyBytes.length != 0) {
            throw new ECBException("message length must be a multiple of the cipher key length, which is " + cipherKeyBytes.length);
        }

        //decrypt
        byte[] decryptedCipherBytes = this.AES(cipherBytes, CipherMode.DECRYPT);

        int loopIterations = decryptedCipherBytes.length/cipherKeyBytes.length;

        //break the decoded text into 16-byte blocks
        byte[][] decryptedBlocks = new byte[loopIterations][16];
        for (int i = 0; i < loopIterations; i++) {
            decryptedBlocks[i] = Arrays.copyOfRange(decryptedCipherBytes, i*16, (i*16)+16);
            //go back through what was already decrypted and check for equality
            for(int j = 0; j < i; j++) {
                if (Arrays.equals(decryptedBlocks[j], decryptedBlocks[i])) {
                    //if we found two bytes that decrypted out the same in this row,
                    // then this is a row that was encrypted with ECB
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Decrypt a message in AES-ECB mode
     *
     * this is the solution to challenge 7
     * @param cipherTextBytes bytes of the cipher text string
     * @param cipherMode one of the public static ints attached to {@link Cipher}
     * @return a string of the decrypted bytes
     * @throws ECBException if a problem with the operation surfaces
     */
    public byte[] AES(byte[] cipherTextBytes, CipherMode cipherMode) throws ECBException {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            Key cipherKey = new SecretKeySpec(cipherKeyBytes, "AES");
            cipher.init(cipherMode.getIntValue(), cipherKey);
            return cipher.doFinal(cipherTextBytes);
        } catch (Exception e) {
            throw new ECBException(String.format("Could not perform %s operation", cipherMode), e);
        }
    }

    public byte[] AESWithPadding(byte[] cipherTextBytes, CipherMode cipherMode) throws ECBException {
        //implement padding
        if (cipherMode == CipherMode.ENCRYPT) {
            cipherTextBytes = applyPadding(cipherTextBytes, cipherKeyBytes.length);
        }

        var theFinal = AES(cipherTextBytes, cipherMode);

        if (cipherMode == CipherMode.DECRYPT) {
            theFinal = stripPadding(theFinal);
        }

        return theFinal;
    }

    public byte[] AESWithConcatenation(byte[] myInput, byte[] unknownInput) throws ECBException {
        byte[] concatenatedInput = ArrayUtils.addAll(myInput, unknownInput);
        return AESWithPadding(concatenatedInput, CipherMode.ENCRYPT);
    }
}
