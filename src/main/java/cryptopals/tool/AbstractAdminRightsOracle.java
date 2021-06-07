package cryptopals.tool;

import java.net.URLEncoder;
import java.nio.charset.Charset;

public abstract class AbstractAdminRightsOracle {

    protected abstract byte[] encrypt(final String input);
    protected abstract String decrypt(final byte[] input);

    public byte[] padAndEncrypt(String inputString) throws Exception {
        //strip out any semicolons and equal signs to protect against hacks and encode
        var sanitizedInput = inputString.replace(";", "");
        sanitizedInput  = inputString.replace("=", "");
        sanitizedInput = URLEncoder.encode(sanitizedInput, Charset.defaultCharset());
        var sb = new StringBuilder();
        sb.append("comment1=cooking%20MCs;userdata=");
        sb.append(sanitizedInput);
        sb.append(";comment2=%20like%20a%20pound%20of%20bacon");
        return encrypt(sb.toString());
    }

    public boolean findAdminInCipherText(byte[] cipherText) throws Exception {
        String decrypted = decrypt(cipherText);
        var mapped = Profile.keyValueParsing(decrypted, ';');
        return mapped.get("admin") != null && Boolean.parseBoolean( (String) mapped.get("admin"));
    }
}
