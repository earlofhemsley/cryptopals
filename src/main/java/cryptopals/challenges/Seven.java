package cryptopals.challenges;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Seven {
    public static String decryptAESInECBMode(String base64EncodedCipherText, String cipherKeyText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] cipherTextBytes = Base64.getDecoder().decode(base64EncodedCipherText);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Key cipherKey = new SecretKeySpec(cipherKeyText.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, cipherKey);
        byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
        return new String(decryptedBytes);
    }


}
