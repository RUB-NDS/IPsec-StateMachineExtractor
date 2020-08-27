/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2ParsingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class TrafficSelectorPayload extends IKEv2Payload {

    protected static final int TRAFFIC_SELECTOR_HEADER_LEN = 8;
    private byte tsNumber = 1;
    private TrafficSelectorSubstructure trafficSelector = new TrafficSelectorSubstructure();

    public TrafficSelectorPayload(IKEPayloadTypeEnum type) {
        super(type);
    }

    public byte getTSNumber() {
        return this.tsNumber;
    }

    public TrafficSelectorSubstructure getTrafficSelector() {
        return this.trafficSelector;
    }

    @Override
    public int getLength() {
        return TRAFFIC_SELECTOR_HEADER_LEN + 16;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(tsNumber);
        baos.write(new byte[]{0x00, 0x00, 0x00}, 0, 3);
        trafficSelector.writeBytes(baos);
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = read4ByteFromStream(bais);
        this.tsNumber = buffer[0];
        if (getTSNumber() != buffer[0]) {
            throw new IKEv2ParsingException("Only one Traffic Selector parsing is supported!");
        }
        if (buffer[1] != 0 || buffer[2] != 0 || buffer[3] != 0) {
            throw new IKEv2ParsingException("Reserved bytes are non-zero!");
        }
        trafficSelector = TrafficSelectorSubstructure.fromStream(bais);
        if (trafficSelector.getLength() < length - TRAFFIC_SELECTOR_HEADER_LEN) {
            throw new IKEv2ParsingException("Input stream ended early after " + (trafficSelector.getLength() + TRAFFIC_SELECTOR_HEADER_LEN) + " bytes (should read " + (length - GENERIC_PAYLOAD_HEADER_LEN) + "bytes)!");
        }
    }

    @Override
    protected void setBody(byte[] body) throws IKEv2ParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
