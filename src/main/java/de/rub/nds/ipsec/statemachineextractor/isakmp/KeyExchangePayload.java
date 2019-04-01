/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayOutputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class KeyExchangePayload extends ISAKMPPayload {

    protected static final int KEX_HEADER_LEN = 4;

    private byte[] keyExchangeData = new byte[0];

    public KeyExchangePayload() {
        super(PayloadTypeEnum.KeyExchange);
    }

    public byte[] getKeyExchangeData() {
        return keyExchangeData;
    }

    public void setKeyExchangeData(byte[] keyExchangeData) {
        this.keyExchangeData = keyExchangeData;
    }

    @Override
    public int getLength() {
        return KEX_HEADER_LEN + keyExchangeData.length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(keyExchangeData, 0, keyExchangeData.length);
    }

}
