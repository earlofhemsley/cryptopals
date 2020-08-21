package cryptopals.utils;

import cryptopals.enums.CipherMode;
import cryptopals.exceptions.BadPaddingRuntimeException;
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

public class CBCPaddingOracle {

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

    public Pair<byte[], byte[]> selectRandomStringAndEncrypt() {
        var r = new Random(System.currentTimeMillis());
        var selectedString = stringList.get(r.nextInt(stringList.size()));
        var ivec = ByteArrayUtil.randomBytes(16);
        var encryptedString = AESinCBCMode(applyPadding(selectedString.getBytes(), key.length), key, ivec, CipherMode.ENCRYPT);
        return Pair.of(ivec, encryptedString);
    }

    public Map<byte[], byte[]> getAllIvecsAndStrings() {
        var map = new LinkedHashMap<byte[], byte[]>();
        for (String s : stringList) {
            var ivec = ByteArrayUtil.randomBytes(16);
            var encryptedString = AESinCBCMode(applyPadding(s.getBytes(), key.length), key, ivec, CipherMode.ENCRYPT);
            map.put(ivec, encryptedString);
        }
        return map;
    }

    public boolean validatePKCS7Padding(byte[] cipherText, byte[] ivec) {
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
