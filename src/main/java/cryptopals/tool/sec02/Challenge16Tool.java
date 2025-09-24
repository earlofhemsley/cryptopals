package cryptopals.tool.sec02;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.XOR;
import cryptopals.utils.ByteArrayUtil;

public class Challenge16Tool {

    private Challenge16Tool() {
        throw new Error("Do not instantiate");
    }

    public static byte[] buildAdminLevelCipherText() {
        //0123456789012345|0123456789012345|0123456789012345|0123456789012345|0123456789...
        //comment1=cooking|%20MCs;userdata=|AAAAAAAAAAAAAAAA|SadminEtrueSAEAA|;comment2=...

        //                                  ^^^^^^^^^^^^^^^^
        // if we edit this block, or apply an edit to it, the edits will roll into the following block
        // and allow us to edit input we know won't be sanitized

        //TODO: split this off into a tool?
        String knownInput = "SadminEtrueSaEaa"; // S for semicolon, E for equals
        String desired = ";admin=true;a=aa";

        byte[] xorResult = XOR.multiByteXOR(knownInput.getBytes(), desired.getBytes());

        //prepend with a block that we don't care if it gets scrambled
        final var hackerInput = "AAAAAAAAAAAAAAAA" + knownInput;
        final var adminLevelCipherText = Challenge16Oracle.firstFunction(hackerInput);

        // apply the bitflipping attack by finding the first block that is changed when we modify the input
        // this is the start of the block that we will want to edit
        final var secondHackerInput = "BAAAAAAAAAAAAAAA" + knownInput;
        final var encrypted2 = Challenge16Oracle.firstFunction(secondHackerInput);
        if (adminLevelCipherText.length != encrypted2.length) {
            throw new CryptopalsException("the two cipher texts are not the same length");
        }

        int idx = 0;
        while (idx < adminLevelCipherText.length && encrypted2[idx] == adminLevelCipherText[idx]) {
            idx++;
        }
        if (idx == 0 || idx == adminLevelCipherText.length - 1) {
            throw new CryptopalsException("Could not find the start of the abusable block");
        }

        var abusableBlock = ByteArrayUtil.sliceByteArray(adminLevelCipherText, idx, xorResult.length);
        var withEditApplied = XOR.multiByteXOR(abusableBlock, xorResult);
        System.arraycopy(withEditApplied, 0, adminLevelCipherText, idx, withEditApplied.length);

        return adminLevelCipherText;
    }
}
