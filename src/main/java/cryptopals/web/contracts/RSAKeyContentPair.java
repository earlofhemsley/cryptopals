package cryptopals.web.contracts;

import cryptopals.tool.sec05.c39.RSA;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RSAKeyContentPair {
    private RSA.Key key;
    private String[] content;
}
