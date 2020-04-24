package cryptopals.utils;

import cryptopals.challenges.Section02;

import java.net.URLEncoder;
import java.nio.charset.Charset;

import javax.crypto.Cipher;

public class Challenge16Oracle {

    private final byte[] key;
    private final byte[] iv;

    public Challenge16Oracle(byte[] key, byte[] iv) {
        this.key = key;
        this.iv = iv;
    }

    public byte[] padAndEncrypt(String inputString) throws Exception {
        //strip out any semicolons and equal signs to protect against hacks and encode
        var sanitizedInput = inputString.replace(";", "");
        sanitizedInput  = inputString.replace("=", "");
        sanitizedInput = URLEncoder.encode(sanitizedInput, Charset.defaultCharset());
        var sb = new StringBuilder();
        sb.append("comment1=cooking%20MCs;userdata=");
        sb.append(sanitizedInput);
        sb.append(";comment2=%20like%20a%20pound%20of%20bacon");
        try {
            return Section02.AESinCBCMode(sb.toString().getBytes(), key, iv, Cipher.ENCRYPT_MODE);
        } catch (Exception e) {
            throw new Exception("could not encrypt", e);
        }
    }

    public boolean findAdminInCipherText(byte[] cipherText) throws Exception {
        byte[] decrypted;
        try {
            decrypted = Section02.AESinCBCMode(cipherText, key, iv, Cipher.DECRYPT_MODE);
            System.out.println(new String(decrypted));
        } catch (Exception e) {
            throw new Exception("could not decrypt", e);
        }
        var mapped = Section02.keyValueParsing(new String(decrypted), ';');
        return mapped.get("admin") != null && Boolean.parseBoolean( (String) mapped.get("admin"));
    }
}
