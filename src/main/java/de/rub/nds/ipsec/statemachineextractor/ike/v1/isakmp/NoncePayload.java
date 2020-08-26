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
import java.io.ByteArrayInputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class NoncePayload extends SimpleBinaryISAKMPPayload {

    public NoncePayload() {
        super(IKEPayloadTypeEnum.Nonce);
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

    public static NoncePayload fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        NoncePayload noncePayload = new NoncePayload();
        SimpleBinaryISAKMPPayload.fromStream(bais, noncePayload);
        return noncePayload;
    }

}
