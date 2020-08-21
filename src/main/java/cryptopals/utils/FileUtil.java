package cryptopals.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * a util for reading files
 */
public class FileUtil {
    private FileUtil() {
        throw new AssertionError("Cannot instantiate FileUtil");
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
}
