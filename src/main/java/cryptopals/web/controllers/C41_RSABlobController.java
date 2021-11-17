package cryptopals.web.controllers;

import cryptopals.tool.MD4;
import cryptopals.tool.sec05.c39.RSA;
import cryptopals.utils.FileUtil;
import cryptopals.web.contracts.RSADecryptRequest;
import cryptopals.web.contracts.RSAKeyContentPair;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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
    public ResponseEntity<RSAKeyContentPair> generateBlobs() {
        String[] lines = FileUtil.readFileAsListOfLines("src/main/resources/c41/when-tillie-ate-the-chili.txt")
                .stream()
                .filter(l -> !l.isBlank())
                .map(l -> RSA.encrypt(l, keyPair.getKey()))
                .toArray(String[]::new);
        for (String line : lines) {
            livenessMap.put(Hex.encodeHexString(md4.getHMAC(line.getBytes())), System.currentTimeMillis() + LIVENESS_INTERVAL);
        }
        return ResponseEntity.ok(new RSAKeyContentPair(keyPair.getKey(), lines));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@Validated @RequestBody final RSADecryptRequest rsaDecryptRequest, BindingResult br) {
        if (br.hasErrors()) {
            return ResponseEntity.badRequest().body("model validation errors");
        }

        final String cipherText = rsaDecryptRequest.getCipherText();
        final String hash = Hex.encodeHexString(md4.getHMAC(cipherText.getBytes()));
        if (livenessMap.containsKey(hash) && (livenessMap.get(hash) - System.currentTimeMillis() > 0)) {
            return ResponseEntity.badRequest().body("ciphertext ttl not done");
        }

        return ResponseEntity.ok(RSA.decrypt(cipherText, keyPair.getRight()));
    }

}
