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
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEPayload;
import java.io.ByteArrayInputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class IKEv2Payload extends GenericIKEPayload {

    public IKEv2Payload(IKEPayloadTypeEnum type) {
        super(type);
    }

    protected abstract void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException;

    protected abstract void setBody(byte[] body) throws GenericIKEParsingException;

    public static Class<? extends IKEv2Payload> getImplementingClass(IKEPayloadTypeEnum type) {
        switch (type) {
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
            case SecurityAssociationv2:
                return SecurityAssociationPayloadv2.class;
            case TrafficSelectorInitiator:
                return TrafficSelectorPayloadInitiator.class;
            case TrafficSelectorResponder:
                return TrafficSelectorPayloadResponder.class;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
    }

}
