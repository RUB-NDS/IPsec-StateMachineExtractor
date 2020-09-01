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
public class NoncePayloadv2 extends SimpleBinaryIKEv2Payload {

    public NoncePayloadv2() {
        super(IKEPayloadTypeEnum.Noncev2);
    }

    public byte[] getNonceData() {
        return getBinaryData();
    }

    public void setNonceData(byte[] nonceData) {
        setBinaryData(nonceData);
    }

    @Override
    public String toString() {
        return "No";
    }

    public static NoncePayloadv2 fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        NoncePayloadv2 noncePayload = new NoncePayloadv2();
        SimpleBinaryIKEv2Payload.fromStream(bais, noncePayload);
        return noncePayload;
    }

}
