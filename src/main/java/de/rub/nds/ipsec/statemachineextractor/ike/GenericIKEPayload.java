/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.FixedLengthByteStreamSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class GenericIKEPayload implements FixedLengthByteStreamSerializable {

    protected static final int GENERIC_PAYLOAD_HEADER_LEN = 4;

    private final IKEPayloadTypeEnum type;
    private IKEPayloadTypeEnum nextPayload = IKEPayloadTypeEnum.NONE;

    public GenericIKEPayload(IKEPayloadTypeEnum type) {
        this.type = type;
    }

    public IKEPayloadTypeEnum getType() {
        return type;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(getGenericPayloadHeader(), 0, GENERIC_PAYLOAD_HEADER_LEN);
    }

    public byte[] getBody() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.writeBytes(baos);
        byte[] bytes = baos.toByteArray();
        byte[] result = new byte[bytes.length - GENERIC_PAYLOAD_HEADER_LEN];
        System.arraycopy(bytes, GENERIC_PAYLOAD_HEADER_LEN, result, 0, result.length);
        return result;
    }

    public IKEPayloadTypeEnum getNextPayload() {
        return nextPayload;
    }

    public void setNextPayload(IKEPayloadTypeEnum nextPayload) {
        this.nextPayload = nextPayload;
    }

    protected byte[] getGenericPayloadHeader() {
        int length = getLength();
        if (length > 0x0000FFFF) {
            throw new IllegalStateException("Payload too large!");
        }
        byte[] genericPayloadHeader = DatatypeHelper.intTo4ByteArray(length);
        genericPayloadHeader[0] = this.getNextPayload().getValue();
        return genericPayloadHeader;
    }

    public int fillGenericPayloadHeaderFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        byte[] genericPayloadHeader = read4ByteFromStream(bais);
        IKEPayloadTypeEnum next = IKEPayloadTypeEnum.get((byte) genericPayloadHeader[0]);
        if (next == null) {
            if (genericPayloadHeader[1] != 0x00) {
                throw new GenericIKEParsingException("Unknown payload type and reserved byte not zero, probably decryption failed!");
            } else {
                throw new GenericIKEParsingException("Unknown payload type: " + String.format("0x%02x", genericPayloadHeader[0]));
            }
        }
        this.setNextPayload(next);
        return ((genericPayloadHeader[2] & 0xff) << 8) | (genericPayloadHeader[3] & 0xff);
    }

    protected static byte[] read4ByteFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        try {
            return DatatypeHelper.read4ByteFromStream(bais);
        } catch (IOException ex) {
            throw new GenericIKEParsingException("Reading from InputStream failed!", ex);
        }
    }
}
