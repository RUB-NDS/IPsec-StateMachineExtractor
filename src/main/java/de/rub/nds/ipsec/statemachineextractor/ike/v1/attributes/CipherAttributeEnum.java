/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPSerializable;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum CipherAttributeEnum implements IKEv1Attribute, ISAKMPSerializable {

    DES_CBC(0x80010001, true),
    IDEA_CBC(0x80010002, true),
    Blowfish_CBC(0x80010003, false),
    RC5_R16_B64_CBC(0x80010004, false),
    TRIPPLEDES_CBC(0x80010005, true),
    CAST_CBC(0x80010006, false),
    AES_CBC(0x80010007, false);

    private final boolean isFixedKeySize;
    private final byte[] bytes;
    
    private CipherAttributeEnum(int value, boolean isFixedKeySize) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        this.isFixedKeySize = isFixedKeySize;
        IKEv1AttributeFactory.register(this, value);
    }

    public boolean isIsFixedKeySize() {
        return isFixedKeySize;
    }
    
    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    @Override
    public void configureCiphersuite(IKEv1Ciphersuite ciphersuite) {
        ciphersuite.setCipher(this);
    }
}
