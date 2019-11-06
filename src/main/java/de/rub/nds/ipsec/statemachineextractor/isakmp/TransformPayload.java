/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ISAKMPTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.IKEv1AttributeFactory;
import de.rub.nds.ipsec.statemachineextractor.ipsec.AHTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ESPTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.IPsecAttributeFactory;
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

    private byte transformNumber = -128;
    private ProtocolTransformIDEnum transformId = ISAKMPTransformIDEnum.KEY_IKE.toProtocolTransformIDEnum();
    private final List<ISAKMPAttribute> attributes = new ArrayList<>();
    private ProtocolIDEnum protocolID;

    public TransformPayload() {
        super(PayloadTypeEnum.Transform);
    }

    @Override
    public int getLength() {
        int length = TRANSFORM_PAYLOAD_HEADER_LEN;
        for (ISAKMPAttribute attribute : attributes) {
            length += attribute.getLength();
        }
        return length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(transformNumber);
        baos.write(transformId.getValue());
        baos.write(0x00);
        baos.write(0x00);
        for (ISAKMPAttribute attribute : attributes) {
            attribute.writeBytes(baos);
        }
    }

    protected void setProtocolID(ProtocolIDEnum protocolID) {
        this.protocolID = protocolID;
    }

    public byte getTransformNumber() {
        return transformNumber;
    }

    public void setTransformNumber(byte transformNumber) {
        this.transformNumber = transformNumber;
    }

    public ProtocolTransformIDEnum getTransformId() {
        return transformId;
    }

    public void setTransformId(ProtocolTransformIDEnum transformId) {
        this.transformId = transformId;
    }

    public void addAttribute(ISAKMPAttribute attribute) {
        attributes.add(attribute);
    }

    public List<ISAKMPAttribute> getAttributes() {
        return Collections.unmodifiableList(attributes);
    }

    private ProtocolTransformIDEnum selectTransformId(byte value) {
        if (protocolID == null) {
            // no further hint, just guess
            return ProtocolTransformIDEnum.getFirstMatch(value);
        }
        switch (protocolID) {
            case ISAKMP:
                return ISAKMPTransformIDEnum.get(value).toProtocolTransformIDEnum();
            case IPSEC_ESP:
                return ESPTransformIDEnum.get(value).toProtocolTransformIDEnum();
            case IPSEC_AH:
                return AHTransformIDEnum.get(value).toProtocolTransformIDEnum();
            default:
                return ProtocolTransformIDEnum.getFirstMatch(value);
        }
    }

    public static TransformPayload fromStream(ByteArrayInputStream bais, ProtocolIDEnum protoID) throws ISAKMPParsingException {
        TransformPayload transformPayload = new TransformPayload();
        transformPayload.setProtocolID(protoID);
        transformPayload.fillFromStream(bais);
        return transformPayload;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = read4ByteFromStream(bais);
        this.setTransformNumber(buffer[0]);
        this.setTransformId(selectTransformId(buffer[1]));
        if ((length - TRANSFORM_PAYLOAD_HEADER_LEN) % 4 != 0) {
            throw new ISAKMPParsingException("Parsing variable length attributes is not supported.");
        }
        for (int i = 0; i < (length - TRANSFORM_PAYLOAD_HEADER_LEN) / 4; i++) {
            int value = ByteBuffer.wrap(read4ByteFromStream(bais)).getInt();
            ISAKMPAttribute attr;
            if (this.getTransformId() == ProtocolTransformIDEnum.ISAKMP_KEY_IKE) {
                attr = IKEv1AttributeFactory.fromInt(value);
            } else {
                attr = IPsecAttributeFactory.fromInt(value);
            }
            this.addAttribute(attr);
        }
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
