/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayInputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class HashPayload extends SimpleBinaryPayload {

    public HashPayload() {
        super(PayloadTypeEnum.Hash);
    }

    public byte[] getHashData() {
        return getBinaryData();
    }

    public void setHashData(byte[] hashData) {
        setBinaryData(hashData);
    }
    
    public static HashPayload fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        HashPayload hashPayload = new HashPayload();
        SimpleBinaryPayload.fromStream(bais, hashPayload);
        return hashPayload;
    }
}
