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

        final byte[] encryptable;
        if (useCbcNotEbc) {
            encryptable = fileBytes;
        } else {
            int offset = -1;
            for (int i = fileBytes.length; i >= 0; i--) {
                if (i % key.length == 0) {
                    offset = fileBytes.length - i;
                    break;
                }
            }
            if (offset < 0) {
                throw new RuntimeException("Could not find determine block length key");
            }

            //get the last n bytes from the image data, where n is the length of the image data less the offset
            encryptable = ByteArrayUtil.sliceEnd(fileBytes, fileBytes.length - offset);
        }

        //retain the first 54 bytes of the image so that we can overwrite the first 54 bytes of bmp header data
        var header = ByteArrayUtil.sliceByteArray(fileBytes, 0, 54);

        //do the encryption
        final byte[] encrypted;
        if (useCbcNotEbc) {
            encrypted = new CBC(key).encryptToByteArray(encryptable, new byte[key.length]);
        } else {
            encrypted = new ECB(key).AES128(encryptable, CipherMode.ENCRYPT);
        }

        // write the encrypted data into a new array that will be written to disk
        int l = Math.max(encrypted.length, fileBytes.length);
        var encryptedImageData = new byte[l];
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
