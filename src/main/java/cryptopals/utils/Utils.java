package cryptopals.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.IntStream;

public class Utils {
    private Utils() {
        throw new AssertionError("Cannot instantiate");
    }


    public static int calculateHammingDistance(byte[] bytes1, byte[] bytes2) {
        if (bytes1.length != bytes2.length) {
            throw new IllegalArgumentException("arguments must be same length");
        }

        int count = 0;
        for (int i = 0; i < bytes1.length; i++) {
            byte one = bytes1[i];
            byte two = bytes2[i];
            byte xor = (byte) (one ^ two);
            for (int j = 0; j < 8; j++) {
                if( ((xor >> j) & 1) == 1 ) {
                    count++;
                }
            }
        }
        return count;
    }

    public static byte[] sliceByteArray(byte[] original, int start, int length) {
        byte[] slice = new byte[length];
        for (int i = 0; i < length; i++) {
            if (start + i < original.length) {
                slice[i] = original[start + i];
            }
        }

        return slice;
    }






    public static String readFileAsWhole(String filePath) throws IOException {
        File f = new File(filePath);
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            int theChar;
            while((theChar = r.read()) != -1) {
                sb.append((char)theChar);
            }
        }
        return sb.toString();
    }

    public static List<String> readFileAsListOfLines(String filePath) throws IOException {
        File f = new File(filePath);
        List<String> lines = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            String line;
            while((line = r.readLine()) != null) {
                lines.add(line);
            }
        }
        return lines;
    }

    public static byte[] randomBytes(int length) {
        byte[] retVal = new byte[length];
        Random r = new Random();
        r.nextBytes(retVal);
        return retVal;
    }

    public static byte[] groupByteNegation(byte[] toNegate) {
        var retval = new byte[toNegate.length];
        for (int i = 0; i < toNegate.length; i++) {
            retval[i] = (byte) (~toNegate[i] & 0xFF);
        }
        return retval;
    }

}
