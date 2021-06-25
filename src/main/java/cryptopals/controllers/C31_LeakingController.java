package cryptopals.controllers;

import static org.springframework.http.ResponseEntity.badRequest;
import static org.springframework.http.ResponseEntity.internalServerError;
import static org.springframework.http.ResponseEntity.ok;

import cryptopals.tool.SHA1;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/c31")
@Slf4j
public class C31_LeakingController {

    private final SHA1 sha1 = new SHA1();

    @GetMapping("/test/{file}")
    public ResponseEntity<String> auth(@PathVariable String file, @RequestParam String signature) {
        if (StringUtils.isBlank(signature)) {
            log.warn("required param not present");
            return badRequest().body("Bad Request");
        }

        //the signature is a hex interpretation of the byte array
        final byte[] sigMac;
        try {
            sigMac = Hex.decode(signature);
        } catch (DecoderException e) {
            log.warn("bad signature -- decoder exception");
            return badRequest().body("Bad Request");
        }

        if (sigMac.length != sha1.getHashLength()) {
            log.warn("bad signature -- wrong hash length");
            return badRequest().body("Bad Request");
        }

        //build the hmac for the submitted message
        final var hmac = sha1.getHMAC(file.getBytes());

        return insecureCompare(hmac, sigMac) ? ok().body("Success") : internalServerError().body("Failure");
    }

    /**
     * given that actually doing the full challenge blows build times substantially,
     * let's surrender all but the first three bytes of a hash
     * @return response entity
     */
    @GetMapping("/cheat/{file}")
    public ResponseEntity<String> cheat(@PathVariable String file) {
        final var hmac = sha1.getHMAC(file.getBytes());
        final String hexified = Hex.toHexString(hmac);
        return ok().body("000000" + hexified.substring(6));
    }

    @SneakyThrows
    private boolean insecureCompare(byte[] hmac, byte[] signature) {
        for (int i = 0; i < hmac.length; i++) {
            if (hmac[i] == signature[i]) {
                Thread.sleep(50);
            } else {
                return false;
            }
        }
        return true;
    }
}
