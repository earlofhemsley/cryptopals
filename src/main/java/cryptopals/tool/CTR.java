package cryptopals.tool;

import cryptopals.enums.CipherMode;
import cryptopals.utils.ByteArrayUtil;

import java.nio.charset.StandardCharsets;

/**
 * a class intended for the implementation of CTR encryption
 */
public class CTR {

    private final XOR xor = new XOR();
    private final ECB ecb;

    public CTR(byte[] key) {
        this.ecb = new ECB(key);
    }

    public byte[] encrypt(String plainText) {
        return whateverCrypt(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public String decrypt(byte[] cipherText) {
        return new String(whateverCrypt(cipherText));
    }

    public void edit(final byte[] cipherText, final int offset, final String newText) {
        // get keystream of length offset plus newText.length rounded up to block size
        final LittleEndianNonce nonce = new LittleEndianNonce();
        final int blockLength = nonce.get().length;
        final int newLength = ((newText.length() + offset) / blockLength) * blockLength + blockLength;
        final int numOfBlocks = newLength / blockLength;
        final byte[] keystream = new byte[newLength];
        for (int block = 0; block < numOfBlocks; block++) {
            var encryptedNonce = ecb.AES(nonce.get(), CipherMode.ENCRYPT);
            System.arraycopy(encryptedNonce, 0, keystream, block * encryptedNonce.length, encryptedNonce.length);
            nonce.increment();
        }

        //get the portion of the keystream we actually care about
        final byte[] ktext = new byte[newText.length()];
        System.arraycopy(keystream, offset, ktext, 0, newText.length());

        // overwrite the ciphertext
        var newTextBytes = newText.getBytes();
        var sub = xor.multiByteXOR(newTextBytes, ktext);
        System.arraycopy(sub, 0, cipherText, offset, sub.length);
    }

    private byte[] whateverCrypt(final byte[] text) {
        //get a new text whose length is a multiple of the nonce length
        final LittleEndianNonce nonce = new LittleEndianNonce();
        final int chunkLength = nonce.get().length;
        //the intricacies of int math in code will make this the next multiple of the nonce length
        final int newLength = (text.length / chunkLength) * chunkLength + chunkLength;
        final byte[] tempText = new byte[newLength];

        System.arraycopy(text, 0, tempText, 0, text.length);

        final byte[] tempResult = new byte[newLength];
        final int numOfChunks = newLength / chunkLength;
        for (int chunkNum = 0; chunkNum < numOfChunks; chunkNum++) {
            //get the first chunk of text
            byte[] chunkOfText = ByteArrayUtil.sliceByteArray(tempText, chunkLength * chunkNum, chunkLength);

            //encrypt the nonce
            var encryptedNonce = ecb.AES(nonce.get(), CipherMode.ENCRYPT);

            //xor against chunkOfText
            var operatedBlock = xor.multiByteXOR(chunkOfText, encryptedNonce);

            //copy to result
            System.arraycopy(operatedBlock, 0, tempResult, operatedBlock.length * chunkNum, operatedBlock.length);

            //increment nonce
            nonce.increment();
        }
        var result = new byte[text.length];
        System.arraycopy(tempResult, 0, result, 0, result.length);
        return result;
    }

}
