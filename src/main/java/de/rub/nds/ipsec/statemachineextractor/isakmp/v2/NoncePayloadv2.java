/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp.v2;

import java.io.ByteArrayInputStream;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SimpleBinaryPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class NoncePayloadv2 extends SimpleBinaryPayload {

    public NoncePayloadv2() {
        super(PayloadTypeEnum.Noncev2);
    }

    public byte[] getNonceData() {
        return getBinaryData();
    }

    public void setNonceData(byte[] nonceData) {
        setBinaryData(nonceData);
    }

    @Override
    public String toString() {
        return "Nov2";
    }

    public static NoncePayloadv2 fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        NoncePayloadv2 noncePayload = new NoncePayloadv2();
        SimpleBinaryPayload.fromStream(bais, noncePayload);
        return noncePayload;
    }

}
