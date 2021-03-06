/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2ParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.IKEv2Attribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.IKEv2AttributeFactory;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class TransformPayloadv2 extends IKEv2Payload {

    protected static final int TRANSFORM_PAYLOAD_HEADER_LEN = 8;

    private ProtocolTransformIDEnum transformId; //= ISAKMPTransformIDEnum.KEY_IKE.toProtocolTransformIDEnum();
    private final List<IKEv2Attribute> attributes = new ArrayList<>();
    private TransformTypeEnum transformType;
    private ProtocolIDEnum protocolID; //?

    public TransformPayloadv2() {
        super(IKEPayloadTypeEnum.Transform);
    }

    @Override
    public int getLength() {
        int length = TRANSFORM_PAYLOAD_HEADER_LEN;
        for (GenericIKEAttribute attribute : attributes) {
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
        for (GenericIKEAttribute attribute : attributes) {
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

    public void addAttribute(IKEv2Attribute attribute) {
        attributes.add(attribute);
    }

    public List<IKEv2Attribute> getAttributes() {
        return Collections.unmodifiableList(attributes);
    }
    
    public void configureCiphersuite(IKEv2Ciphersuite ciphersuite) {
        switch (transformType) {
            case ENCR:
                ciphersuite.setCipher(EncryptionAlgorithmTransformEnum.get(this.transformId.getValue()));
                break;
            case PRF:
                ciphersuite.setPrf(PseudoRandomFunctionTransformEnum.get(this.transformId.getValue()));
                break;
            case INTEG:
                ciphersuite.setAuthMethod(IntegrityAlgorithmTransformEnum.get(this.transformId.getValue()));
                break;
            case DH:
                ciphersuite.setDhGroup(DHGroupTransformEnum.get(this.transformId.getValue()));
                break;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
        this.attributes.forEach(attr -> attr.configureCiphersuite(ciphersuite));
    }

    private ProtocolTransformIDEnum DHselectTransformId(byte value) {
        if (protocolID == null) {
            // no further hint, just guess
            return ProtocolTransformIDEnum.getFirstMatch(value);
        }
        switch (protocolID) {
            case ISAKMP_IKE:
                return DHGroupTransformEnum.get(value).toProtocolTransformIDEnum();
            default:
                return ProtocolTransformIDEnum.getFirstMatch(value);
        }
    }

    private ProtocolTransformIDEnum ENCRselectTransformId(byte value) {
        if (protocolID == null) {
            // no further hint, just guess
            return ProtocolTransformIDEnum.getFirstMatch(value);
        }
        switch (protocolID) {
            case ISAKMP_IKE:
                return EncryptionAlgorithmTransformEnum.get(value).toProtocolTransformIDEnum();
            default:
                return ProtocolTransformIDEnum.getFirstMatch(value);
        }
    }

    private ProtocolTransformIDEnum PRFselectTransformId(byte value) {
        if (protocolID == null) {
            // no further hint, just guess
            return ProtocolTransformIDEnum.getFirstMatch(value);
        }
        switch (protocolID) {
            case ISAKMP_IKE:
                return PseudoRandomFunctionTransformEnum.get(value).toProtocolTransformIDEnum();
            default:
                return ProtocolTransformIDEnum.getFirstMatch(value);
        }
    }

    private ProtocolTransformIDEnum INTEGselectTransformId(byte value) {
        if (protocolID == null) {
            // no further hint, just guess
            return ProtocolTransformIDEnum.getFirstMatch(value);
        }
        switch (protocolID) {
            case ISAKMP_IKE:
                return IntegrityAlgorithmTransformEnum.get(value).toProtocolTransformIDEnum();
            default:
                return ProtocolTransformIDEnum.getFirstMatch(value);
        }
    }

    public static TransformPayloadv2 fromStream(ByteArrayInputStream bais, ProtocolIDEnum protoID) throws GenericIKEParsingException {
        TransformPayloadv2 transformPayloadv2 = new TransformPayloadv2();
        transformPayloadv2.setProtocolID(protoID);
        transformPayloadv2.fillFromStream(bais);
        return transformPayloadv2;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = read4ByteFromStream(bais);
        this.setTransformType(TransformTypeEnum.get(buffer[0]));
        switch (transformType) {
            case ENCR:
                this.setTransformId(ENCRselectTransformId(buffer[3]));
                break;
            case PRF:
                this.setTransformId(PRFselectTransformId(buffer[3]));
                break;
            case INTEG:
                this.setTransformId(INTEGselectTransformId(buffer[3]));
                break;
            case DH:
                this.setTransformId(DHselectTransformId(buffer[3]));
                break;
            default:
                this.setTransformId(ProtocolTransformIDEnum.getFirstMatch(buffer[2]));
                break;
        }
        int processedLength = 0;
        while (processedLength < (length - TRANSFORM_PAYLOAD_HEADER_LEN)) {
            IKEv2Attribute attr;
            attr = IKEv2AttributeFactory.fromStream(bais);
            this.addAttribute(attr);
            processedLength += attr.getLength();
        }
    }

    @Override
    protected void setBody(byte[] body) throws IKEv2ParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
