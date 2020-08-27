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
public class TrafficSelectorInitiatorPayload extends TrafficSelectorPayload {

    public TrafficSelectorInitiatorPayload() {
        super(IKEPayloadTypeEnum.TrafficSelectorInitiator);
    }

    @Override
    public String toString() {
        return "TSi";
    }

    public static TrafficSelectorInitiatorPayload fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        TrafficSelectorInitiatorPayload tsiPayload = new TrafficSelectorInitiatorPayload();
        tsiPayload.fillFromStream(bais);
        return tsiPayload;
    }
}
