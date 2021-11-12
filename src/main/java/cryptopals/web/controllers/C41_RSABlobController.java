package cryptopals.web.controllers;

import cryptopals.tool.MD4;
import cryptopals.tool.sec05.c39.RSA;
import cryptopals.utils.FileUtil;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/rsa")
public class C41_RSABlobController {
    /**
     * the live-ness interval for entries in the map
     */
    private static final long LIVENESS_INTERVAL = 150000;

    private final Pair<RSA.Key, RSA.Key> keyPair = RSA.keyGen(1024);
    private final MD4 md4 = new MD4();
    private final Map<String, Long> livenessMap = new HashMap<>();

    @GetMapping("/blobs")
    public ResponseEntity<String[]> generateBlobs() {
        String[] lines = FileUtil.readFileAsListOfLines("src/main/resources/c41/the-jabberwocky.txt")
                .stream()
                .filter(l -> !l.isBlank())
                .map(l -> RSA.encrypt(l, keyPair.getKey()))
                .toArray(String[]::new);
        return ResponseEntity.ok(lines);
    }
}
