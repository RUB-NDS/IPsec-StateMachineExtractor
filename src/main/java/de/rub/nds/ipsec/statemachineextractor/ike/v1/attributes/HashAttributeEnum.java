/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.ike.BasicIKEAttribute;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum HashAttributeEnum implements ISAKMPAttribute, BasicIKEAttribute {
    
    MD5(0x80020001),
    SHA1(0x80020002),
    TIGER(0x80020003);

    protected static final int FORMAT_TYPE = 0x8002;
    private final byte[] bytes;

    private HashAttributeEnum(int value) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        IKEv1AttributeFactory.register(this, value);
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    @Override
    public void configureCiphersuite(IKEv1Ciphersuite ciphersuite) {
        ciphersuite.setHash(this);
    }

}