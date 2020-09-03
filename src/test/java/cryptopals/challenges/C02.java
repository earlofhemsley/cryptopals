package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.XOR;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

/**
 * Fixed XOR
 * Write a function that takes two equal-length buffers and produces their XOR combination.
 *
 * If your function works properly, then when you feed it the string:
 *
 * 1c0111001f010100061a024b53535009181c
 * ... after hex decoding, and when XOR'd against:
 *
 * 686974207468652062756c6c277320657965
 * ... should produce:
 *
 * 746865206b696420646f6e277420706c6179
 */
public class C02 {
    @Test
    public void twoTest() throws DecoderException {
        String input1 = "1c0111001f010100061a024b53535009181c";
        String input2 = "686974207468652062756c6c277320657965";
        String result = new XOR().hexStringFixedXor(input1, input2);
        assertEquals("746865206b696420646f6e277420706c6179", result);
    }
}
