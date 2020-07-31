/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.EncryptedPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.IdentificationPayloadInitiator;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.IdentificationPayloadResponder;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.AuthenticationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.NotificationPayloadv2;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class ISAKMPPayload implements ISAKMPSerializable {

    protected static final int ISAKMP_PAYLOAD_HEADER_LEN = 4;

    private final PayloadTypeEnum type;
    private PayloadTypeEnum nextPayload = PayloadTypeEnum.NONE;

    public ISAKMPPayload(PayloadTypeEnum type) {
        this.type = type;
    }

    public PayloadTypeEnum getType() {
        return type;
    }

    /**
     * @return the length of the full payload, including the generic payload
     * header
     */
    @Override
    public abstract int getLength();

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(getGenericPayloadHeader(), 0, ISAKMP_PAYLOAD_HEADER_LEN);
    }
    
    public byte[] getBody() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.writeBytes(baos);
        byte[] bytes = baos.toByteArray();
        byte[] result = new byte[bytes.length - ISAKMP_PAYLOAD_HEADER_LEN];
        System.arraycopy(bytes, ISAKMP_PAYLOAD_HEADER_LEN, result, 0, result.length);
        return result;
    }
    
    protected abstract void setBody(byte[] body) throws ISAKMPParsingException;
    
    protected abstract void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException;

    public PayloadTypeEnum getNextPayload() {
        return nextPayload;
    }

    public void setNextPayload(PayloadTypeEnum nextPayload) {
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

    protected int fillGenericPayloadHeaderFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        byte[] genericPayloadHeader = read4ByteFromStream(bais);
        PayloadTypeEnum next = PayloadTypeEnum.get((byte)genericPayloadHeader[0]);
        if (next == null) {
            if (genericPayloadHeader[1] != 0x00) {
                throw new ISAKMPParsingException("Unknown payload type and reserved byte not zero, probably decryption failed!");
            } else {
                throw new ISAKMPParsingException("Unknown payload type: " + String.format("0x%02x", genericPayloadHeader[0]));
            }
        }
        this.setNextPayload(next);
        return ((genericPayloadHeader[2] & 0xff) << 8) | (genericPayloadHeader[3] & 0xff);
    }
    
    protected static byte[] read4ByteFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        try {
            return DatatypeHelper.read4ByteFromStream(bais);
        } catch (IOException ex) {
            throw new ISAKMPParsingException("Reading from InputStream failed!", ex);
        }
    }
    
    public static Class<? extends ISAKMPPayload> getImplementingClass(PayloadTypeEnum type) {
        switch(type) {
            case Delete:
                return DeletePayload.class;
            case Hash:
                return HashPayload.class;
            case Identification:
                return IdentificationPayload.class;
            case KeyExchange:
                return KeyExchangePayload.class;
            case Nonce:
                return NoncePayload.class;
            case Notification:
                return NotificationPayload.class;
            case Proposal:
                return ProposalPayload.class;
            case SecurityAssociation:
                return SecurityAssociationPayload.class;
            case Transform:
                return TransformPayload.class;
            case VendorID:
                return VendorIDPayload.class;
            case IdentificationInitiator:
            	return IdentificationPayloadInitiator.class;
            case IdentificationResponder:
            	return IdentificationPayloadResponder.class;
            case Authentication:
            	return AuthenticationPayload.class;
            case Notify:
            	return NotificationPayloadv2.class;
            case EncryptedAndAuthenticated:
            	return EncryptedPayload.class;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
    }

}
