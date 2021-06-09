package cryptopals.tool;

import java.net.URLEncoder;
import java.nio.charset.Charset;

public abstract class AbstractAdminRightsOracle {

    protected abstract byte[] encrypt(final String input);
    protected abstract String decrypt(final byte[] input);

    public byte[] padAndEncrypt(String inputString) {
        //strip out any semicolons and equal signs to protect against hacks and encode
        var sanitizedInput = inputString.replace(";", "");
        sanitizedInput  = inputString.replace("=", "");
        sanitizedInput = URLEncoder.encode(sanitizedInput, Charset.defaultCharset());
        String sb = "comment1=cooking%20MCs;userdata=" +
                sanitizedInput +
                ";comment2=%20like%20a%20pound%20of%20bacon";
        return encrypt(sb);
    }

    public boolean findAdminInCipherText(byte[] cipherText) {
        String decrypted = decrypt(cipherText);
        var mapped = Profile.keyValueParsing(decrypted, ';');
        return mapped.get("admin") != null && Boolean.parseBoolean( (String) mapped.get("admin"));
    }
}
