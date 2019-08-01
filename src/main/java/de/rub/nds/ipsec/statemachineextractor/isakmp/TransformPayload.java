/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.IKEv1Attribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.IKEv1AttributeFactory;
import static de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload.read4ByteFromStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TransformPayload extends ISAKMPPayload {

    protected static final int TRANSFORM_PAYLOAD_HEADER_LEN = 8;

    private byte transformNumber;
    private byte transformId = 0x01; //KEY_IKE
    private final List<IKEv1Attribute> attributes = new ArrayList<>();

    public TransformPayload() {
        super(PayloadTypeEnum.Transform);
    }

    @Override
    public int getLength() {
        int length = TRANSFORM_PAYLOAD_HEADER_LEN;
        for (IKEv1Attribute attribute : attributes) {
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
        for (IKEv1Attribute attribute : attributes) {
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

    public void addIKEAttribute(IKEv1Attribute attribute) {
        attributes.add(attribute);
    }

    public List<IKEv1Attribute> getAttributes() {
        return Collections.unmodifiableList(attributes);
    }

    public static TransformPayload fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        TransformPayload transformPayload = new TransformPayload();
        int length = transformPayload.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = read4ByteFromStream(bais);
        transformPayload.setTransformNumber(buffer[0]);
        transformPayload.setTransformId(buffer[1]);
        if ((length - TRANSFORM_PAYLOAD_HEADER_LEN) % 4 != 0) {
            throw new ISAKMPParsingException("Parsing variable length attributes is not supported.");
        }
        for (int i = 0; i < (length - TRANSFORM_PAYLOAD_HEADER_LEN) / 4; i++) {
            int value = ByteBuffer.wrap(read4ByteFromStream(bais)).getInt();
            IKEv1Attribute attr = IKEv1AttributeFactory.fromInt(value);
            transformPayload.addIKEAttribute(attr);
        }
        return transformPayload;
    }
}
