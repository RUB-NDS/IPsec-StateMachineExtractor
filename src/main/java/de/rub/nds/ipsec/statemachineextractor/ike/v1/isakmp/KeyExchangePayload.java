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
public class KeyExchangePayload extends SimpleBinaryISAKMPPayload {

    public KeyExchangePayload() {
        super(IKEPayloadTypeEnum.KeyExchange);
    }

    public byte[] getKeyExchangeData() {
        return getBinaryData();
    }

    public void setKeyExchangeData(byte[] keyExchangeData) {
        setBinaryData(keyExchangeData);
    }

    @Override
    public String toString() {
        return "KE";
    }
    
    public static KeyExchangePayload fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        KeyExchangePayload keyExchangePayload = new KeyExchangePayload();
        SimpleBinaryISAKMPPayload.fromStream(bais, keyExchangePayload);
        return keyExchangePayload;
    }

}
