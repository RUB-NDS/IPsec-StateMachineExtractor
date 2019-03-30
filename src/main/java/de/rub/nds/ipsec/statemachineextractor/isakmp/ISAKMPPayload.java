/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayOutputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class ISAKMPPayload {

    protected static final int ISAKMP_PAYLOAD_HEADER_LEN = 4;
    
    private final PayloadTypeEnum type;

    private PayloadTypeEnum nextPayload = PayloadTypeEnum.NONE;

    /**
     * @return the length of the full payload, including the generic payload
     * header
     */
    public abstract int getLength();

    public byte[] getBytes() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(getGenericPayloadHeader(), 0, ISAKMP_PAYLOAD_HEADER_LEN);
        writeBytes(baos);
        return baos.toByteArray();
    }

    protected abstract void writeBytes(ByteArrayOutputStream baos);

    public ISAKMPPayload(PayloadTypeEnum type) {
        this.type = type;
    }

    public PayloadTypeEnum getType() {
        return type;
    }

    protected void setNextPayload(PayloadTypeEnum nextPayload) {
        this.nextPayload = nextPayload;
    }

    private byte[] getGenericPayloadHeader() {
        int length = getLength();
        if (length > 0x0000FFFF) {
            throw new IllegalStateException("Payload too large");
        }
        byte[] genericPayloadHeader = DatatypeHelper.intTo4ByteArray(length);
        genericPayloadHeader[0] = nextPayload.getValue();
        return genericPayloadHeader;
    }
}
