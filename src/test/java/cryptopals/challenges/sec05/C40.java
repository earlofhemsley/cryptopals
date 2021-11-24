package cryptopals.challenges.sec05;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.sec05.RSA;
import cryptopals.tool.sec05.c40.RSACubeRooter;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.RepeatedTest;

/**
 * Implement an E=3 RSA Broadcast attack
 * Assume you're a Javascript programmer. That is, you're using a naive hand-rolled RSA to encrypt without padding.
 *
 * Assume you can be coerced into encrypting the same plaintext three times, under three different public keys.
 * You can; it's happened.
 *
 * Then an attacker can trivially decrypt your message, by:
 *
 * Capturing any 3 of the ciphertexts and their corresponding pubkeys
 * Using the CRT to solve for the number represented by the three ciphertexts
 * (which are residues mod their respective pubkeys)
 * Taking the cube root of the resulting number
 * The CRT says you can take any number and represent it as the combination of a series of residues mod a series of
 * moduli. In the three-residue case, you have:
 *
 * result =
 *   (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
 *   (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
 *   (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
 *
 * where:
 *  c_0, c_1, c_2 are the three respective residues mod
 *  n_0, n_1, n_2
 *
 *  m_s_n (for n in 0, 1, 2) are the product of the moduli
 *  EXCEPT n_n --- ie, m_s_1 is n_0 * n_2
 *
 *  N_012 is the product of all three moduli
 *  To decrypt RSA using a simple cube root, leave off the final modulus operation;
 *  just take the raw accumulated result and cube-root it.
 */
public class C40 {

    @RepeatedTest(100)
    void root() {
        Pair<RSA.Key, RSA.Key> key1;
        Pair<RSA.Key, RSA.Key> key2;
        Pair<RSA.Key, RSA.Key> key3;

        //build keys until we know we don't have duplicate keys
        do {
             key1 = RSA.keyGen(196, 3);
             key2 = RSA.keyGen(196, 3);
             key3 = RSA.keyGen(196, 3);
        } while (key1.getKey().equals(key2.getKey()) ||
                key2.getKey().equals(key3.getKey()) ||
                key1.getKey().equals(key3.getKey())
        );

        //encrypt a plaintext with these keys
        final String plainText = "Chancellor on brink of second bailout for banks";
        final String c1 = RSA.encrypt(plainText, key1.getKey());
        final String c2 = RSA.encrypt(plainText, key2.getKey());
        final String c3 = RSA.encrypt(plainText, key3.getKey());

        //send the cipher texts to the rooter to see if it can be broken
        final String decrypted = RSACubeRooter.root(Pair.of(c1, key1.getKey()), Pair.of(c2, key2.getKey()),
                Pair.of(c3, key3.getKey()));

        assertEquals(plainText, decrypted);
    }
}
