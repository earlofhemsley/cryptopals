package cryptopals.utils;

import cryptopals.exceptions.CryptopalsException;
import lombok.SneakyThrows;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * a util for reading files
 */
public class FileUtil {
    private FileUtil() {
        throw new AssertionError("Cannot instantiate FileUtil");
    }

    public static String readFileAsWhole(String filePath) {
        File f = new File(filePath);
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            int theChar;
            while((theChar = r.read()) != -1) {
                sb.append((char)theChar);
            }
        } catch (IOException e) {
            throw new CryptopalsException("File IO problem", e);
        }
        return sb.toString();
    }

    public static List<String> readFileAsListOfLines(String filePath) {
        File f = new File(filePath);
        List<String> lines = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            String line;
            while((line = r.readLine()) != null) {
                lines.add(line);
            }
        } catch (IOException e) {
            throw new CryptopalsException("File IO problem", e);
        }
        return lines;
    }

    @SneakyThrows
    public static String readLineNOfFile(final String filePath, final int n) {
        try (Stream<String> lines = Files.lines(Paths.get(filePath))) {
            return lines.skip(n)
                    .findFirst()
                    .orElseThrow(() -> new CryptopalsException("could not read line " + n))
                    .trim();
        }
    }

    @SneakyThrows
    public static byte[] readFileAsByteArray(final String filepath) {
        final var path = Paths.get(filepath);
        if (Files.exists(path)) {
            return Files.readAllBytes(path);
        }
        return new byte[]{};
    }

    public static boolean writeFile(final String filepath, final byte[] contents) {
        try {
            final var path = Paths.get(filepath);
            if (Files.exists(path)) {
                Files.delete(path);
            }
            Files.write(path, contents);
        } catch (IOException e) {
            return false;
        }
        return true;
    }
}
