package cryptopals.tool.sec06.c42;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class ASN1UtilTests {

    @ParameterizedTest
    @MethodSource("supplyArgs")
    void ensureValidPadding(final byte[] subject, final int expectedIndex) {
        assertEquals(expectedIndex, ASN1Util.findASN1Start(subject));
    }

    static Stream<Arguments> supplyArgs() {
        return Stream.of(
                arguments(new byte[4], -1),
                arguments(new byte[10], -1),
                arguments(new byte[] {1, 1, -1, 0, 0}, -1),
                arguments(new byte[] {0, 0, -1, 0, 0}, -1),
                arguments(new byte[] {0, 1, -1, 3, 0}, -1),
                arguments(new byte[] {0, 1, -1, -1, -1, 0, 0}, -1),
                arguments(new byte[] {0, 1, -1, -1, -1, -1, 0, 0}, 7),
                arguments(new byte[] {0, 1, -1, -1, -1, -1, -1, 0}, -1),
                arguments(new byte[] {0, 1, -1, -1, -1, -1, -1, 0, 0}, 8)
        );
    }
}
