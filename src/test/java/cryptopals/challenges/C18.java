package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertEquals;

import cryptopals.tool.CTR;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Implement CTR, the stream cipher mode
 * The string
 * 77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
 * decrypts to something approximating English in CTR mode, which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:
 * <pre>
 *     key=YELLOW SUBMARINE
 *     nonce=0
 *     format=64 bit unsigned little endian nonce,
 *     64 bit little endian block count (byte count / 16)
 * </pre>
 *
 * CTR mode is very simple.
 *
 * Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream, which is XOR'd against the plaintext.
 *
 * For instance, for the first 16 bytes of a message with these parameters:
 *
 * keystream = AES("YELLOW SUBMARINE",
 * "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
 * ... for the next 16 bytes:
 *
 * keystream = AES("YELLOW SUBMARINE",
 * "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
 * ... and then:
 *
 * keystream = AES("YELLOW SUBMARINE",
 * "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
 * CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.
 *
 * Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.
 *
 * Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.
 *
 * This is the only block cipher mode that matters in good code.
 * Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers, because most of what we want
 * to encrypt is better described as a stream than as a sequence of blocks. Daniel Bernstein once quipped to Phil
 * Rogaway that good cryptosystems don't need the "decrypt" transforms. Constructions like CTR are what he was talking about.
 */
public class C18 {
    //look at the java.nio.ByteBuffer class. it might be able to do little endian for you without you having to
    // work hard

    @Test
    public void ctrChallenge() {
        final CTR ctr = new CTR("YELLOW SUBMARINE".getBytes(StandardCharsets.UTF_8));
        byte[] decoded = Base64.getDecoder().decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
        assertEquals("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", ctr.decrypt(decoded));
    }

}
