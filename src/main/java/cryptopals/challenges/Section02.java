package cryptopals.challenges;

import cryptopals.utils.Utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Section02 {
    /**
     * given a message and a block size, implement pkcs7 padding on the message to make the message conform to the block size
     *
     * this is the solution to challenge nine
     *
     * @param messageBytes
     * @param blockSize
     * @return
     */
    public static byte[] implementPKCS7Padding(byte[] messageBytes, int blockSize) {
        if (blockSize >= 256 || blockSize <= 0) {
            throw new IllegalArgumentException("Block size can only be between 1 and 255, inclusive");
        }
        int numOfPaddingBytes = blockSize - messageBytes.length % blockSize;

        int newLength = (int) Math.ceil((double) messageBytes.length / blockSize) * blockSize;
        if (newLength == messageBytes.length) {
            newLength += blockSize;
        }

        byte[] paddedMessage = Arrays.copyOf(messageBytes, newLength);

        for (int i = messageBytes.length; i<messageBytes.length + numOfPaddingBytes; i++) {
            paddedMessage[i] = (byte) numOfPaddingBytes;
        }

        return paddedMessage;
    }

    public static byte[] AESinCBC(byte[] textBytes, final byte[] cipherKeyBytes, final byte[] iv, int cipherMode) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        if (cipherMode != Cipher.ENCRYPT_MODE && cipherMode != Cipher.DECRYPT_MODE) {
            throw new IllegalArgumentException("cipherMode must be Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE");
        }

        //block size will be the size of the cipher key
        //make sure the iv and the cipherkey are the same size
        if (cipherKeyBytes.length != iv.length) {
            throw new IllegalArgumentException("cipher key and init vector must be the same length");
        }

        if (cipherMode == Cipher.ENCRYPT_MODE) {
            //pad the message only if encrypting
            textBytes = Section02.implementPKCS7Padding(textBytes, cipherKeyBytes.length);
        } else if (textBytes.length % cipherKeyBytes.length != 0) {
            //make sure the message length is a multiple of the iv
            throw new IllegalArgumentException("When decrypting, the message's length must be a multiple of the key's length");
        }

        byte[] resultBytes = new byte[textBytes.length];
        byte[] previousBlock = iv;

        for (int n = 0; n < textBytes.length; n+=iv.length) {
            //get the nth block
            byte[] nthBlock = Utils.sliceByteArray(textBytes, n, iv.length);

            byte[] currentBlock;
            switch (cipherMode) {
                case Cipher.ENCRYPT_MODE:
                    byte[] xorNthBlock = Utils.multiByteXOR(nthBlock, previousBlock);
                    currentBlock = Section01.AESInECBMode(xorNthBlock, cipherKeyBytes, cipherMode);
                    previousBlock = currentBlock;
                    break;
                case Cipher.DECRYPT_MODE:
                    byte[] decNthBlock = Section01.AESInECBMode(nthBlock, cipherKeyBytes, cipherMode);
                    currentBlock = Utils.multiByteXOR(decNthBlock, previousBlock);
                    previousBlock = nthBlock;
                    break;
                default:
                    throw new IllegalArgumentException("illegal cipher mode");
            }

            for (int i = 0; i < iv.length; i++ ) {
                resultBytes[n+i] = currentBlock[i];
            }
        }

        //strip padding if decrypting
        if (cipherMode == Cipher.DECRYPT_MODE) {
            //get last byte
            int numToStrip = resultBytes[resultBytes.length - 1];
            int numToKeep = resultBytes.length - numToStrip;
            resultBytes = Utils.sliceByteArray(resultBytes, 0, numToKeep);
        }

        return resultBytes;
    }
}
