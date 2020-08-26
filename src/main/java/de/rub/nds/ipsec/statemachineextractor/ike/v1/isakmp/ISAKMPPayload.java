/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEPayload;
import java.io.ByteArrayInputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class ISAKMPPayload extends GenericIKEPayload {

    public ISAKMPPayload(IKEPayloadTypeEnum type) {
        super(type);
    }

    protected abstract void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException;

    protected abstract void setBody(byte[] body) throws GenericIKEParsingException;

    public static Class<? extends ISAKMPPayload> getImplementingClass(IKEPayloadTypeEnum type) {
        switch (type) {
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
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
    }

}
