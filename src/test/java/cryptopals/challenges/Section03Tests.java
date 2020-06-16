package cryptopals.challenges;

import static org.junit.jupiter.api.Assertions.assertTrue;

import cryptopals.utils.CBCPaddingOracle;
import cryptopals.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.Map;

public class Section03Tests {

//    @Test
    public void challenge17() {
        var oracle = new CBCPaddingOracle();
        var masterMap = oracle.getAllIvecsAndStrings();
        for (Map.Entry<byte[], byte[]> pair : masterMap.entrySet()) {


        }
    }
}
