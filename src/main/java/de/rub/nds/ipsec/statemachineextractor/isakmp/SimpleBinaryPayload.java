/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class SimpleBinaryPayload extends ISAKMPPayload {

    protected static final int HEADER_LEN = 4;

    private byte[] binaryData = new byte[0];

    public SimpleBinaryPayload(PayloadTypeEnum type) {
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
    
    protected static SimpleBinaryPayload fromStream(ByteArrayInputStream bais, SimpleBinaryPayload payload) throws ISAKMPParsingException {
        payload.fillFromStream(bais);
        return payload;
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        this.setBinaryData(body);
    }
    
    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = new byte[length - HEADER_LEN];
        int readBytes;
        try {
            readBytes = bais.read(buffer);
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        if (readBytes < length - HEADER_LEN) {
            throw new ISAKMPParsingException("Input stream ended early after " + readBytes + " bytes (should read " + (length - HEADER_LEN) + " bytes)!");
        }
        this.setBody(buffer);
        if (length != this.getLength()) {
            throw new ISAKMPParsingException("Payload lengths differ - Computed: " + this.getLength() + "vs. Received: " + length + "!");
        }
    }
    
}
