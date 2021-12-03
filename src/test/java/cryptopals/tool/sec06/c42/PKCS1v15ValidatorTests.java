package cryptopals.tool.sec06.c42;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class PKCS1v15ValidatorTests {

    @ParameterizedTest
    @MethodSource("supplyArgs")
    void ensureValidPadding(final byte[] subject, final int expectedIndex) {
        assertEquals(expectedIndex, PKCS1v15Validator.findAsnStartingIndex(subject));
    }

    static Stream<Arguments> supplyArgs() {
        return Stream.of(
                arguments(new byte[4], -1),
                arguments(new byte[10], -1),
                arguments(new byte[] {1, 1, (byte) 0xff, 0, 0}, -1),
                arguments(new byte[] {0, 0, (byte) 0xff, 0, 0}, -1),
                arguments(new byte[] {0, 1, (byte) 0xff, 3, 0}, -1),
                arguments(new byte[] {0, 1, (byte) 0xff, 0, 0}, 4),
                arguments(new byte[] {0, 1, (byte) 0xff, (byte) 0xff, 0, 0}, 5),
                arguments(new byte[] {0, 1, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0, 0}, 6)
        );
    }
}
