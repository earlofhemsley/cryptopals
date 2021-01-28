package cryptopals.tool;

import cryptopals.enums.CipherMode;
import cryptopals.exceptions.CryptopalsException;
import cryptopals.exceptions.ECBException;
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

    private byte[] whateverCrypt(final byte[] text) {
        //get a new text whose length is a multiple of the nonce length
        final LittleEndianNonce nonce = new LittleEndianNonce();
        final int chunkLength = nonce.get().length;
        //the intricacies of int math in code will make this the next multiple of the nonce length
        final int newLength = (text.length / chunkLength) * chunkLength + chunkLength;
        final byte[] newText = new byte[newLength];

        System.arraycopy(text, 0, newText, 0, text.length);

        final byte[] tempResult = new byte[newLength];
        try {
            final int numOfChunks = newLength / chunkLength;
            for (int chunkNum = 0; chunkNum < numOfChunks; chunkNum++) {
                //get the first chunk of text
                byte[] chunkOfText = ByteArrayUtil.sliceByteArray(newText, chunkLength * chunkNum, chunkLength);

                //encrypt the nonce
                var encryptedNonce = ecb.AES(nonce.get(), CipherMode.ENCRYPT);

                //xor against chunkOfText
                var operatedBlock = xor.multiByteXOR(chunkOfText, encryptedNonce);

                //copy to result
                System.arraycopy(operatedBlock, 0, tempResult, operatedBlock.length * chunkNum, operatedBlock.length);

                //increment nonce
                nonce.increment();
            }
        } catch (ECBException e) {
            throw new CryptopalsException("Could not perform operation", e);
        }
        var result = new byte[text.length];
        System.arraycopy(tempResult, 0, result, 0, result.length);
        return result;
    }

}
