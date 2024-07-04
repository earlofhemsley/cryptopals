package cryptopals.tool.sec02;

import cryptopals.enums.CipherMode;
import cryptopals.tool.ECB;
import cryptopals.utils.ByteArrayUtil;
import lombok.extern.slf4j.Slf4j;

import java.util.Base64;
import java.util.Random;

@Slf4j
public class Challenge14Oracle {
    private static final byte[] RANDOM_PREFIX = ByteArrayUtil.randomBytes(new Random().nextInt(100));
    private static final ECB ECB = new ECB(ByteArrayUtil.randomBytes(16));
    private static final byte[] MYSTERY_BYTES = Base64.getDecoder().decode(
            ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
                    "YnkK").getBytes());

    private Challenge14Oracle() {
        throw new Error("Do not instantiate");
    }

    public static byte[] speakProphecy(byte[] input) {
        byte[] prefixPlusInputPlusMysteryBytes = ByteArrayUtil.concatenate(RANDOM_PREFIX, input, MYSTERY_BYTES);
        return ECB.AES128WPadding(prefixPlusInputPlusMysteryBytes, CipherMode.ENCRYPT);
    }
}
