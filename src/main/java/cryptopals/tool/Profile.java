package cryptopals.tool;

import cryptopals.enums.CipherMode;
import cryptopals.utils.ByteArrayUtil;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class Profile {
    private static final byte[] challenge13key = ByteArrayUtil.randomBytes(16); //the fact that this is static means the key is shared among all instances

    private final Map<String,Object> propertyMap = new LinkedHashMap<>();
    private final ECB ecb = new ECB(challenge13key);

    /**
     * this constructor assigns the role of user
     * @param email the email
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
     * @param encryptedProfileArray the encrypted profile array
     */
    public Profile(byte[] encryptedProfileArray) {
        final byte[] decryptedProfileBytes = ecb.AES128WPadding(encryptedProfileArray, CipherMode.DECRYPT);
        final String decryptedProfileString = new String(decryptedProfileBytes);
        final Map<String,Object> kvPairs = keyValueParsing(decryptedProfileString);
        propertyMap.putAll(kvPairs);
    }

    public Object get(String key) {
        return propertyMap.get(key);
    }

    public byte[] encryptProfile() {
        return ecb.AES128WPadding(this.profileFor().getBytes(), CipherMode.ENCRYPT);
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
