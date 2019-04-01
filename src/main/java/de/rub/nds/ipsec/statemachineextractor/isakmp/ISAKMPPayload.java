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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class ISAKMPPayload implements ISAKMPSerializable {

    protected static final int ISAKMP_PAYLOAD_HEADER_LEN = 4;

    private final PayloadTypeEnum type;
    private PayloadTypeEnum nextPayload = PayloadTypeEnum.NONE;

    public ISAKMPPayload(PayloadTypeEnum type) {
        this.type = type;
    }

    public PayloadTypeEnum getType() {
        return type;
    }

    /**
     * @return the length of the full payload, including the generic payload
     * header
     */
    @Override
    public abstract int getLength();

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(getGenericPayloadHeader(), 0, ISAKMP_PAYLOAD_HEADER_LEN);
    }

    public PayloadTypeEnum getNextPayload() {
        return nextPayload;
    }

    public void setNextPayload(PayloadTypeEnum nextPayload) {
        this.nextPayload = nextPayload;
    }

    protected byte[] getGenericPayloadHeader() {
        int length = getLength();
        if (length > 0x0000FFFF) {
            throw new IllegalStateException("Payload too large");
        }
        byte[] genericPayloadHeader = DatatypeHelper.intTo4ByteArray(length);
        genericPayloadHeader[0] = nextPayload.getValue();
        return genericPayloadHeader;
    }

    protected int fillGenericPayloadHeaderFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        byte[] genericPayloadHeader = read4ByteFromStream(bais);
        nextPayload = PayloadTypeEnum.get((byte)genericPayloadHeader[0]);
        return ((genericPayloadHeader[2] & 0xff) << 8) | (genericPayloadHeader[3] & 0xff);
    }
    
    protected static byte[] read4ByteFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        byte[] buffer = new byte[4];
        try {
            int read = bais.read(buffer);
            if (read != 4) {
                throw new ISAKMPParsingException("Reading from InputStream failed!");
            }
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        return buffer;
    }

}
