package cryptopals.tool.sec02;

import cryptopals.enums.CipherMode;
import cryptopals.tool.ECB;
import cryptopals.utils.ByteArrayUtil;

import java.util.Base64;

public class Challenge12Oracle {
    private Challenge12Oracle() {
        throw new Error("Do not instantiate");
    }
    private static final ECB ECB = new ECB(ByteArrayUtil.randomBytes(16));

    private static final byte[] MYSTERY_BYTES = Base64.getDecoder().decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
            "YnkK");

    public static byte[] speakProphecy(byte[] input) {
        final var concatenated = ByteArrayUtil.concatenate(input, MYSTERY_BYTES);
        return ECB.AES128WPadding(concatenated, CipherMode.ENCRYPT);
    }
}
