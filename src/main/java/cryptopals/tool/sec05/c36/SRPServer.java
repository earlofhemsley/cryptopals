package cryptopals.tool.sec05.c36;

import cryptopals.exceptions.CryptopalsException;
import cryptopals.tool.sec05.NetworkNode;
import cryptopals.tool.sec05.NetworkRouter;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@Getter
public class SRPServer implements NetworkNode {
    private final String name;
    private final NetworkRouter network;
    private final BigInteger g;
    private final BigInteger k;
    private final BigInteger n;

    private final Map<String, NetworkRouter.SRPReg> registry = new HashMap<>();

    public SRPServer(String name, NetworkRouter network, BigInteger g, BigInteger k, BigInteger n) {
        this.name = name;
        this.network = network;
        this.g = g;
        this.k = k;
        this.n = n;

        network.register(this);
    }

    /**
     * routing method
     * @param packet incoming package
     * @return response packet
     */
    @Override
    public NetworkRouter.Packet receivePacket(NetworkRouter.Packet packet) {
        if (!StringUtils.equals(packet.getDestination(), this.name)) {
            throw new CryptopalsException(String.format("got a packet intended for %s but I am %s",
                    packet.getDestination(), this.name));
        }

        final Object responsePayload;
        if (packet.getPayload() instanceof NetworkRouter.SRPReg) {
            responsePayload = receiveRegRequest((NetworkRouter.SRPReg) packet.getPayload());
        } else {
            throw new CryptopalsException("Unable to handle incoming packet because it was of an " +
                    "unrecognized type");
        }

        return new NetworkRouter.Packet(this.name, packet.getSource(), responsePayload);
    }

    private boolean receiveRegRequest(NetworkRouter.SRPReg incoming) {
        registry.put(incoming.getUsername(), incoming);
        return true;
    }
}
