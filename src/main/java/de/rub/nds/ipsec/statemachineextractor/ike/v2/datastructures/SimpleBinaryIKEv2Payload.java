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
import de.rub.nds.ipsec.statemachineextractor.ike.SimpleBinaryPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2ParsingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class SimpleBinaryIKEv2Payload extends IKEv2Payload implements SimpleBinaryPayload {

    byte[] binaryData = new byte[0];

    public SimpleBinaryIKEv2Payload(IKEPayloadTypeEnum type) {
        super(type);
    }

    protected byte[] getBinaryData() {
        return binaryData.clone();
    }

    protected void setBinaryData(byte[] binaryData) {
        this.binaryData = binaryData;
    }

    @Override
    public int getLength() {
        return HEADER_LEN + binaryData.length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(binaryData, 0, binaryData.length);
    }

    @Override
    protected void setBody(byte[] body) throws IKEv2ParsingException {
        this.setBinaryData(body);
    }

    protected static SimpleBinaryIKEv2Payload fromStream(ByteArrayInputStream bais, SimpleBinaryIKEv2Payload payload) throws GenericIKEParsingException {
        payload.fillFromStream(bais);
        return payload;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        if (length < HEADER_LEN) {
            throw new IKEv2ParsingException("Payload length too short!");
        }
        byte[] buffer = new byte[length - HEADER_LEN];
        int readBytes;
        try {
            readBytes = bais.read(buffer);
        } catch (IOException ex) {
            throw new IKEv2ParsingException(ex);
        }
        if (readBytes < length - HEADER_LEN) {
            throw new IKEv2ParsingException("Input stream ended early after " + readBytes + " bytes (should read " + (length - HEADER_LEN) + " bytes)!");
        }
        this.setBody(buffer);
        if (length != this.getLength()) {
            throw new IKEv2ParsingException("Payload lengths differ - Computed: " + this.getLength() + "vs. Received: " + length + "!");
        }
    }

}
