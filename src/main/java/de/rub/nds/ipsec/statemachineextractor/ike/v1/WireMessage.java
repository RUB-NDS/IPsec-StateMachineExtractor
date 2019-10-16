/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import java.nio.ByteBuffer;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class WireMessage {

    final ByteBuffer data;
    final ISAKMPMessage message;
    final boolean isSentByMe;

    public WireMessage(byte[] data, ISAKMPMessage message, boolean isSentByMe) {
        this.data = ByteBuffer.wrap(data);
        this.message = message;
        this.isSentByMe = isSentByMe;
    }

    public ByteBuffer getData() {
        return data.duplicate();
    }

    public ISAKMPMessage getMessage() {
        return message;
    }

    public boolean isIsSentByMe() {
        return isSentByMe;
    }

}
