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
import java.io.ByteArrayInputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IdentificationPayloadResponder extends IdentificationPayload {

    public IdentificationPayloadResponder() {
        super(IKEPayloadTypeEnum.IdentificationResponder);
    }

    public void setIDr() {
        setIDx();
    }

    public byte[] getIDr() {
        return getIDx();
    }

    @Override
    public String toString() {
        return "IDr";
    }

    public static IdentificationPayloadResponder fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        IdentificationPayloadResponder identificationPayload = new IdentificationPayloadResponder();
        identificationPayload.fillFromStream(bais);
        return identificationPayload;
    }
}
