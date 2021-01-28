package cryptopals.tool;

import cryptopals.enums.CipherMode;
import cryptopals.exceptions.ECBException;
import cryptopals.utils.ByteArrayUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class Profile {
    private static final byte[] challenge13key = ByteArrayUtil.randomBytes(16);

    private final Map<String,Object> propertyMap = new LinkedHashMap<>();
    private final ECB ecb = new ECB(challenge13key);

    /**
     * this constructor assigns the role of user
     * @param email
     */
    public Profile(String email) {
        email = email.replace("=","");
        email = email.replace("&","");

        propertyMap.put("email", email);
        propertyMap.put("uid", 10);
        propertyMap.put("role", "user");
    }

    /**
     * this constructor will take an encrypted profile,
     * assume the encryption was never broken
     * decrypt and parse the encrypted profile
     * and set all the values in the property map as such
     * @param encryptedProfileArray
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws NoSuchPaddingException
     */
    public Profile(byte[] encryptedProfileArray) throws ECBException {
        propertyMap.putAll(keyValueParsing(new String(ecb.AESWithPadding(encryptedProfileArray, CipherMode.DECRYPT))));
    }

    public Object get(String key) {
        return propertyMap.get(key);
    }

    public byte[] encryptProfile() throws ECBException {
        return ecb.AESWithPadding(this.profileFor().getBytes(), CipherMode.ENCRYPT);
    }

    public static Map<String, Object> keyValueParsing(String theString) {
        return keyValueParsing(theString, '&');
    }

    public static Map<String, Object> keyValueParsing(String theString, char delimiter) {
        String[] pairs = theString.split(String.valueOf(delimiter));
        Map<String, Object> retval = new HashMap<>();
        for (String pair : pairs) {
            if(!pair.contains("=")) {
                continue;
            }
            String[] kv = pair.split("=");
            retval.put(kv[0], kv[1]);
        }

        return retval;
    }

    public String profileFor() {
        return propertyMap.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue().toString())
                .collect(Collectors.joining("&"));
    }
}
