/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class NoncePayload extends SimpleBinaryPayload {

    public NoncePayload() {
        super(PayloadTypeEnum.Nonce);
    }

    public byte[] getNonceData() {
        return getBinaryData();
    }

    public void setNonceData(byte[] nonceData) {
        setBinaryData(nonceData);
    }

}
