package cryptopals.tool.sec02;

import cryptopals.tool.CBC;
import cryptopals.tool.Profile;

import java.net.URLEncoder;
import java.nio.charset.Charset;

/**
 * This tool aids in the accomplishment of challenge 16
 */
public class Challenge16Tool {

    private final CBC cbc;
    private final byte[] iv;

    public Challenge16Tool(byte[] key, byte[] iv) {
        this.cbc = new CBC(key);
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
            return cbc.encryptToByteArray(sb.toString().getBytes(), iv);
        } catch (Exception e) {
            throw new Exception("could not encrypt", e);
        }
    }

    public boolean findAdminInCipherText(byte[] cipherText) throws Exception {
        String decrypted;
        try {
            decrypted = cbc.decryptAsString(cipherText, iv);
            System.out.println(decrypted);
        } catch (Exception e) {
            throw new Exception("could not decrypt", e);
        }
        var mapped = Profile.keyValueParsing(decrypted, ';');
        return mapped.get("admin") != null && Boolean.parseBoolean( (String) mapped.get("admin"));
    }
}
