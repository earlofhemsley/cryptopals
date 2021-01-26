package cryptopals.tool;

import static cryptopals.utils.PKCS7Util.applyPadding;
import static cryptopals.utils.PKCS7Util.stripPadding;

import cryptopals.enums.CipherMode;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
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
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public boolean detectECBInCipherBytes(byte[] cipherBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        Key cipherKey = new SecretKeySpec(cipherKeyBytes, "AES");

        //decrypt
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        byte[] decryptedCipherBytes = cipher.doFinal(cipherBytes);

        if (cipherBytes.length % cipherKeyBytes.length != 0) {
            throw new IllegalBlockSizeException("message length must be a multiple of the cipher key length, which is " + cipherKeyBytes.length);
        }

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
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] AESInECBMode(byte[] cipherTextBytes, CipherMode cipherMode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        Key cipherKey = new SecretKeySpec(cipherKeyBytes, "AES");
        cipher.init(cipherMode.getIntValue(), cipherKey);
        return cipher.doFinal(cipherTextBytes);
    }

    public byte[] AESinECBModeWPadding(byte[] cipherTextBytes, CipherMode cipherMode) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        //implement padding
        if (cipherMode == CipherMode.ENCRYPT) {
            cipherTextBytes = applyPadding(cipherTextBytes, cipherKeyBytes.length);
        }

        var theFinal = AESInECBMode(cipherTextBytes, cipherMode);

        if (cipherMode == CipherMode.DECRYPT) {
            theFinal = stripPadding(theFinal);
        }

        return theFinal;
    }

    public byte[] AESinEBCModeWConcatenation(byte[] myInput, byte[] unknownInput) throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException {
        byte[] concatenatedInput = ArrayUtils.addAll(myInput, unknownInput);
        return AESinECBModeWPadding(concatenatedInput, CipherMode.ENCRYPT);
    }
}
