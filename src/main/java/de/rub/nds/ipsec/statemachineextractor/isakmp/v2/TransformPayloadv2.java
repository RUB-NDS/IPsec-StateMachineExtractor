/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp.v2;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPAttribute;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ISAKMPTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.IKEv1AttributeFactory;
import de.rub.nds.ipsec.statemachineextractor.ipsec.AHTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ESPTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.IPsecAttributeFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TransformPayloadv2 extends ISAKMPPayload {

    protected static final int TRANSFORM_PAYLOAD_HEADER_LEN = 8;

    private ProtocolTransformIDEnum transformId; //= ISAKMPTransformIDEnum.KEY_IKE.toProtocolTransformIDEnum();
    private final List<ISAKMPAttribute> attributes = new ArrayList<>();
    private TransformTypeEnum transformType;
    private ProtocolIDEnum protocolID; //?

    public TransformPayloadv2() {
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
        baos.write(transformType.getValue());
        baos.write(0x00);
        baos.write(0x00);
        baos.write(transformId.getValue());
        for (ISAKMPAttribute attribute : attributes) {
            attribute.writeBytes(baos);
        }
    }
    
    public void setTransformType(TransformTypeEnum transformType) {
        this.transformType = transformType;
    }
    
    public TransformTypeEnum getTransformType() {
        return transformType;
    }

    protected void setProtocolID(ProtocolIDEnum protocolID) {
        this.protocolID = protocolID;
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

    public static TransformPayloadv2 fromStream(ByteArrayInputStream bais, ProtocolIDEnum protoID) throws ISAKMPParsingException {
        TransformPayloadv2 transformPayloadv2 = new TransformPayloadv2();
        transformPayloadv2.setProtocolID(protoID);
        transformPayloadv2.fillFromStream(bais);
        return transformPayloadv2;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = read4ByteFromStream(bais);
        this.setTransformId(selectTransformId(buffer[1]));
        int processedLength = 0;
        while (processedLength < (length - TRANSFORM_PAYLOAD_HEADER_LEN)) {
            ISAKMPAttribute attr;
            if (this.getTransformId() == ProtocolTransformIDEnum.ISAKMP_KEY_IKE) {
                attr = IKEv1AttributeFactory.fromStream(bais);
            } else {
                attr = IPsecAttributeFactory.fromStream(bais);
            }
            this.addAttribute(attr);
            processedLength += attr.getLength();
        }
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
