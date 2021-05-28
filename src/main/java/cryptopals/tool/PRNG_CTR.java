package cryptopals.tool;

import cryptopals.utils.ByteArrayUtil;

import java.nio.charset.StandardCharsets;

/**
 * an implementation of a counter stream encryption tool
 * that depends on a PRNG to generate keystream
 *
 * this tool uses {@link MT19937_32} to generate its keystream
 */
public class PRNG_CTR {
    private static final int BLOCK_LENGTH = 4;

    private final short key;
    private final XOR xor = new XOR();

    public PRNG_CTR(final short key) {
        this.key = key;
    }

    /**
     * encrypt a plain text
     * @param plainText the plain text
     * @return an encrypted byte array
     */
    public byte[] encrypt(final String plainText) {
        return whateverCrypt(plainText.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * decrypt a cipher text
     * @param cipherText the cipher text
     * @return the decrypted plain text
     */
    public String decrypt(final byte[] cipherText) {
        return new String(whateverCrypt(cipherText));
    }

    private byte[] whateverCrypt(final byte[] text) {
        final var streamer = new MT19937_32(key);

        final int newLength = (text.length / BLOCK_LENGTH) * BLOCK_LENGTH + BLOCK_LENGTH;
        final var newText = new byte[newLength];

        System.arraycopy(text, 0, newText, 0, text.length);

        final byte[] temp = new byte[newLength];

        final int numOfBlocks = newLength / BLOCK_LENGTH;
        for (int b = 0; b < numOfBlocks; b++) {
            //get a block of text
            final byte[] block = ByteArrayUtil.sliceByteArray(newText, BLOCK_LENGTH * b, BLOCK_LENGTH);

            //get some keystream and convert it to byte array
            final byte[] stream = ByteArrayUtil.intToByteArray(streamer.nextInt());

            //xor stream against the text
            final byte[] operatedBlock = xor.multiByteXOR(block, stream);

            //copy
            System.arraycopy(operatedBlock, 0, temp, operatedBlock.length * b, operatedBlock.length);
        }

        var result = new byte[text.length];
        System.arraycopy(temp, 0, result, 0, result.length);
        return result;
    }
}
