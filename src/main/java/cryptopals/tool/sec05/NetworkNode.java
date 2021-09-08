package cryptopals.tool.sec05;

import cryptopals.exceptions.CryptopalsException;

public interface NetworkNode {
    String getName();
    NetworkRouter.Packet receivePacket(NetworkRouter.Packet packet);

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
