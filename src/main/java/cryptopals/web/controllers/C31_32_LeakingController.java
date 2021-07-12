package cryptopals.web.controllers;

import static org.springframework.http.ResponseEntity.badRequest;
import static org.springframework.http.ResponseEntity.internalServerError;
import static org.springframework.http.ResponseEntity.ok;

import cryptopals.tool.SHA1;
import cryptopals.web.config.properties.LeakingProperties;
import lombok.RequiredArgsConstructor;
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
@RequestMapping("/leak")
@Slf4j
@RequiredArgsConstructor
public class C31_32_LeakingController {

    private final SHA1 sha1 = new SHA1();
    private final LeakingProperties leakingProps;
    private final Object lockingObj = new Object();

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
        final byte[] hmac;
        synchronized (lockingObj) {
            hmac = sha1.getHMAC(file.getBytes());
        }

        return insecureCompare(hmac, sigMac) ? ok().body("Success") : internalServerError().body("Failure");
    }

    @SneakyThrows
    private boolean insecureCompare(byte[] hmac, byte[] signature) {
        for (int i = 0; i < hmac.length; i++) {
            if (hmac[i] == signature[i]) {
                Thread.sleep(leakingProps.getDelay());
            } else {
                return false;
            }
        }
        return true;
    }
}
