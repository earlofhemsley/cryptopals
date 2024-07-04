package cryptopals.tool;


import cryptopals.enums.CipherMode;
import cryptopals.utils.ByteArrayUtil;
import cryptopals.utils.FileUtil;

public class BitmapCipherTool {
    private BitmapCipherTool() {
        throw new Error("Do not instantiate");
    }

    /**
     * @param filepath     the file to be encrypted
     * @param useCbcNotEbc if true, will encrypt with cbc
     */
    public static void EncryptBitmapImage(String filepath, String keyString, boolean useCbcNotEbc) {
        //TODO: should validate the extension on the filepath that it is indeed a .bmp file

        final byte[] key = keyString.getBytes();
        final var fileBytes = FileUtil.readFileAsByteArray(filepath);

        //retain the first 54 bytes of the image so that we can overwrite the first 54 bytes of bmp header data
        var header = ByteArrayUtil.sliceByteArray(fileBytes, 0, 54);

        //do the encryption
        final byte[] encrypted;
        if (useCbcNotEbc) {
            encrypted = new CBC(key).encryptToByteArray(fileBytes, new byte[key.length]);
        } else {
            encrypted = new ECB(key).AES128WPadding(fileBytes, CipherMode.ENCRYPT);
        }

        // write the encrypted data into a new array that will be written to disk
        int len = Math.max(encrypted.length, fileBytes.length);
        var encryptedImageData = new byte[len];
        for (int i = encryptedImageData.length - 1, j = encrypted.length - 1; j >= 0 && i >= 0; ) {
            encryptedImageData[i] = encrypted[j];
            i--;
            j--;
        }
        System.arraycopy(header, 0, encryptedImageData, 0, header.length);

        if (!FileUtil.writeFile(String.format("%s.enc.%s.bmp", filepath, useCbcNotEbc ? "cbc" : "ecb"), encryptedImageData)) {
            throw new RuntimeException("failed to write the encrypted file");
        }
    }
}
