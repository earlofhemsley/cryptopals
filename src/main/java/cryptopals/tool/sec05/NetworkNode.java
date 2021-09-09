package cryptopals.tool.sec05;

import cryptopals.exceptions.CryptopalsException;
import org.apache.commons.lang3.StringUtils;

public interface NetworkNode {
    String getName();
    NetworkRouter.Packet receivePacket(NetworkRouter.Packet packet);

    default void validatePacket(NetworkRouter.Packet packet) {
        if (!StringUtils.equals(packet.getDestination(), getName())) {
            throw new CryptopalsException(String.format("This packet is meant for %s, but I am %s",
                    packet.getDestination(), getName()));
        }
    }

    default <T> T validateAndReturnPayloadByType(final Object payload, final Class<T> type) {
        if(!(type.isAssignableFrom(payload.getClass()))) {
            throw new CryptopalsException(String.format("Expected a %s but instead got a %s",
                    type.getSimpleName(), payload.getClass().getSimpleName()
            ));
        }
        @SuppressWarnings("unchecked") T response =  (T) payload;
        return response;
    }
}
