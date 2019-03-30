/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ikev1.IKEAttribute;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TransformPayload extends ISAKMPPayload {

    protected static final int TRANSFORM_PAYLOAD_HEADER_LEN = 8;
    
    private byte transformNumber;
    private byte transformId = 0x01; //KEY_IKE
    private final List<IKEAttribute> attributes = new ArrayList<>();

    public TransformPayload() {
        super(PayloadTypeEnum.Transform);
    }
    
    @Override
    public int getLength() {
        int length = TRANSFORM_PAYLOAD_HEADER_LEN;
        for (IKEAttribute attribute : attributes) {
            length += attribute.getLength();
        }
        return length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(transformNumber);
        baos.write(transformId);
        baos.write(0x00);
        baos.write(0x00);
        for (IKEAttribute attribute : attributes) {
            attribute.writeBytes(baos);
        }
    }

    public byte getTransformNumber() {
        return transformNumber;
    }

    public void setTransformNumber(byte transformNumber) {
        this.transformNumber = transformNumber;
    }

    public byte getTransformId() {
        return transformId;
    }

    public void setTransformId(byte transformId) {
        this.transformId = transformId;
    }
    
    public void addIKEAttribute(IKEAttribute attribute) {
        attributes.add(attribute);
    }

}
