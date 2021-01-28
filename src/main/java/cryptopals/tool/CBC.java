package cryptopals.tool;

import cryptopals.enums.CipherMode;
import cryptopals.exceptions.CryptopalsException;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.PKCS7Util;

/**
 * implementation of a CBC encryption / decryption tool.
 */
public class CBC {

    private final byte[] cipherKeyBytes;

    public CBC(byte[] cipherKeyBytes) {
        this.cipherKeyBytes = cipherKeyBytes;
    }

    private byte[] AESinCBCMode(byte[] textBytes, byte[] iv, CipherMode cipherMode)  {
        //make sure the iv and the cipherkey are the same size
        if (cipherKeyBytes.length != iv.length) {
            throw new IllegalArgumentException("cipher key and init vector must be the same length");
        }

        if (cipherMode == null) {
            throw new IllegalArgumentException("Cipher mode is required");
        }

        //block size will be the size of the cipher key
        if (textBytes.length % cipherKeyBytes.length != 0) {
            throw new IllegalArgumentException("length of textBytes must be a multiple of the length of the cipher key. did you forget to pad your message?");
        }

        final ECB ecb = new ECB(cipherKeyBytes);

        final XOR xor = new XOR();
        byte[] resultBytes = new byte[textBytes.length];
        byte[] previousBlock = iv;

        for (int n = 0; n < textBytes.length; n+=iv.length) {
            //get the nth block
            byte[] nthBlock = ByteArrayUtil.sliceByteArray(textBytes, n, iv.length);

            byte[] currentBlock;
            try {
                switch (cipherMode) {
                    case ENCRYPT:
                        byte[] xorNthBlock = xor.multiByteXOR(nthBlock, previousBlock);
                        currentBlock = ecb.AES(xorNthBlock, cipherMode);
                        previousBlock = currentBlock;
                        break;
                    case DECRYPT:
                        byte[] decNthBlock = ecb.AES(nthBlock, cipherMode);
                        currentBlock = xor.multiByteXOR(decNthBlock, previousBlock);
                        previousBlock = nthBlock;
                        break;
                    default:
                        throw new IllegalArgumentException("illegal cipher mode");
                }
            } catch (Exception e) {
                throw new CryptopalsException("could not execute the desired operation", e);
            }

            System.arraycopy(currentBlock, 0, resultBytes, n, iv.length);
        }

        return resultBytes;
    }

    public String decryptAsString(byte[] messageBytes, byte[] ivec) {
        return new String(decryptAsByteArray(messageBytes, ivec));
    }

    public byte[] decryptAsByteArray(byte[] messageBytes, byte[] ivec) {
        return PKCS7Util.stripPadding(AESinCBCMode(messageBytes, ivec, CipherMode.DECRYPT));
    }

    public byte[] encryptToByteArray(byte[] textBytes, byte[] ivec) {
        return AESinCBCMode(PKCS7Util.applyPadding(textBytes, cipherKeyBytes.length), ivec, CipherMode.ENCRYPT);
    }
}
