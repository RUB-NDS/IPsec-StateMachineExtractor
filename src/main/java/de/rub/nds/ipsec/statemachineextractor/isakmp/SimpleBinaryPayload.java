/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayOutputStream;

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
    
}
