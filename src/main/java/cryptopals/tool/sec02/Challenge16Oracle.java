package cryptopals.tool.sec02;

import cryptopals.tool.CBC;
import cryptopals.utils.ByteArrayUtil;

public class Challenge16Oracle {
    private Challenge16Oracle() {
        throw new Error("Do not instantiate");
    }

    private static final int BLOCK_SIZE = 16;
    private static final CBC CIPHER = new CBC(ByteArrayUtil.randomBytes(BLOCK_SIZE));
    private static final byte[] IV = ByteArrayUtil.randomBytes(BLOCK_SIZE);
    private static final String CONSTANT_PREFIX = "comment1=cooking%20MCs;userdata=";
    private static final String CONSTANT_SUFFIX = ";comment2=%20like%20a%20pound%20of%20bacon";

    public static byte[] firstFunction(String arbitraryInput) {
        final var sanitized = arbitraryInput.replace(";", "%3b").replace("=", "%3d");
        final var combined = String.format("%s%s%s", CONSTANT_PREFIX, sanitized, CONSTANT_SUFFIX);
        return CIPHER.encryptToByteArray(combined.getBytes(), IV);
    }

    public static boolean secondFunction(byte[] cipherText) {
        final var decrypted = CIPHER.decryptAsString(cipherText, IV);
        return decrypted.contains(";admin=true;");
    }
}
