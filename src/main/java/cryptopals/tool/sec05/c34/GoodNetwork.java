package cryptopals.tool.sec05.c34;

import cryptopals.tool.sec05.NetworkRouter;

public class GoodNetwork extends NetworkRouter {
    @Override
    public Packet route(Packet packet) {
        validatePartyRegistry(packet.getDestination());
        return registry.get(packet.getDestination()).receivePacket(packet);
    }
}
