package cryptopals.tool.sec03;

import cryptopals.enums.CipherMode;
import cryptopals.exceptions.BadPaddingRuntimeException;
import cryptopals.utils.ByteArrayUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static cryptopals.challenges.Section02.AESinCBCMode;
import static cryptopals.utils.PKCS7Util.applyPadding;
import static cryptopals.utils.PKCS7Util.stripPadding;

/**
 * A tool for challenge 17, formerly known as the CBC Padding Oracle
 */
public class Challenge17Tool {

    private static final List<String> stringList = new ArrayList<>();
    static {
        stringList.add("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=");
        stringList.add("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=");
        stringList.add("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==");
        stringList.add("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==");
        stringList.add("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl");
        stringList.add("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==");
        stringList.add("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==");
        stringList.add("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=");
        stringList.add("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=");
        stringList.add("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93");
    }
    private static final byte[] key = ByteArrayUtil.randomBytes(16);

    /**
     * The first function should select at random one of 10 strings,
     * generate a random AES key (which it should save for all future encryptions),
     * pad the string out to the 16-byte AES block size
     * and CBC-encrypt it under that key, providing the caller the ciphertext and IV.
     * @return pair of cipher text and iv
     */
    public Pair<byte[], byte[]> selectRandomStringAndEncrypt() {
        var r = new Random(System.currentTimeMillis());
        var selectedString = stringList.get(r.nextInt(stringList.size()));
        var ivec = ByteArrayUtil.randomBytes(16);
        var encryptedString = AESinCBCMode(applyPadding(selectedString.getBytes(), key.length), key, ivec, CipherMode.ENCRYPT);
        return Pair.of(ivec, encryptedString);
    }

    /**
     * This function does the same as {@link Challenge17Tool#selectRandomStringAndEncrypt()}
     * except that it will return a map of _all_ strings and _all_ ivecs for comprehensive testing
     * @return map of ciphertext - iv pairs
     */
    public Map<byte[], byte[]> getAllIvecsAndStrings() {
        var map = new LinkedHashMap<byte[], byte[]>();
        for (String s : stringList) {
            var ivec = ByteArrayUtil.randomBytes(16);
            var encryptedString = AESinCBCMode(applyPadding(s.getBytes(), key.length), key, ivec, CipherMode.ENCRYPT);
            map.put(ivec, encryptedString);
        }
        return map;
    }

    /**
     * The second function should consume the ciphertext produced by the first function,
     * decrypt it, check its padding, and return true or false depending on whether the padding is valid.
     */
    public boolean askTheOracleIsPaddingValid(byte[] cipherText, byte[] ivec) {
        var decrypted = AESinCBCMode(cipherText, key, ivec, CipherMode.DECRYPT);
        try {
            //don't catch an exception, it's good padding
            stripPadding(decrypted);
            return true;
        } catch (BadPaddingRuntimeException e) {
            //if it's bad padding, then we return false
            return false;
        }
    }

    public boolean decryptionIsPresentInOriginalPlainTexts(byte[] decryption) {
        String candidate = new String(stripPadding(decryption));
        return stringList.stream().anyMatch(s -> StringUtils.equals(candidate, s));
    }
}
