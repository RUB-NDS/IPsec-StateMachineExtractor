/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor;

import java.nio.ByteBuffer;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class WireMessage {

    final ByteBuffer data;
    final SerializableMessage message;
    final boolean isSentByMe;

    public WireMessage(byte[] data, SerializableMessage message, boolean isSentByMe) {
        this.data = ByteBuffer.wrap(data);
        this.message = message;
        this.isSentByMe = isSentByMe;
    }

    public ByteBuffer getData() {
        return data.duplicate();
    }

    public SerializableMessage getMessage() {
        return message;
    }

    public boolean isSentByMe() {
        return isSentByMe;
    }

}
