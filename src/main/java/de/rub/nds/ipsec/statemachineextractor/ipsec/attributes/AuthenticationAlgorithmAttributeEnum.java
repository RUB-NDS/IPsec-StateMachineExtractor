/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec.attributes;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum AuthenticationAlgorithmAttributeEnum implements IPsecAttribute, ISAKMPSerializable {

    RESERVED(0x80050000),
    HMAC_MD5(0x80050001),
    HMAC_SHA(0x80050002),
    DES_MAC(0x80050003),
    KPDK(0x80050004);

    protected static final int FORMAT_TYPE = 0x8005;
    private final byte[] bytes;

    private AuthenticationAlgorithmAttributeEnum(int value) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        IPsecAttributeFactory.register(this, value);
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }
    
    public String macJCEName() {
        switch (this) {
            case HMAC_MD5:
                return "HmacMD5";
            case HMAC_SHA:
                return "HmacSHA1";
            default:
                throw new UnsupportedOperationException("Not supported yet!");
        }
    }
}
