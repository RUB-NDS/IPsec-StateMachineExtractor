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
import java.io.ByteArrayOutputStream;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SimpleBinaryPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class KeyExchangePayloadv2 extends SimpleBinaryPayload {

    private final ProtocolTransformIDEnum dhGroup = ProtocolTransformIDEnum.IKEV2_DH_1024_MODP;

    public KeyExchangePayloadv2() {
        super(PayloadTypeEnum.KeyExchangev2);
    }

    public byte[] getKeyExchangeData() {
        return getBinaryData();
    }

    public void setKeyExchangeData(byte[] keyExchangeData) {
        ByteArrayOutputStream keyExchangeDatav2 = new ByteArrayOutputStream();
        keyExchangeDatav2.write(0x00);
        keyExchangeDatav2.write(dhGroup.getValue());
        keyExchangeDatav2.write(0x00);
        keyExchangeDatav2.write(0x00);
        keyExchangeDatav2.write(keyExchangeData, 0, keyExchangeData.length);
        setBinaryData(keyExchangeDatav2.toByteArray());
    }

    @Override
    public String toString() {
        return "KEv2";
    }
    
    public static KeyExchangePayloadv2 fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        KeyExchangePayloadv2 keyExchangePayload = new KeyExchangePayloadv2();
        SimpleBinaryPayload.fromStream(bais, keyExchangePayload);
        return keyExchangePayload;
    }

}
