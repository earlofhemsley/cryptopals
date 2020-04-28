package cryptopals.enums;

import javax.crypto.Cipher;

public enum CipherMode {
    ENCRYPT(Cipher.ENCRYPT_MODE),
    DECRYPT(Cipher.DECRYPT_MODE)
    ;

    private final int intValue;

    CipherMode(final int intValue) {
        this.intValue = intValue;
    }

    public int getIntValue() {
        return intValue;
    }
}
