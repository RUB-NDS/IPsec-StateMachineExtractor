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
public enum KeyLengthAttributeEnum implements IKEv1Attribute, ISAKMPSerializable {

    L128(0x800e0080, 16),
    L192(0x800e00C0, 24),
    L256(0x800e0100, 32);

    private final byte[] bytes;
    private final int keySize;

    private KeyLengthAttributeEnum(int value, int size) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        this.keySize = size;
        IKEv1AttributeFactory.register(this, value);
    }

    public int getKeySize() {
        return this.keySize;
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

    @Override
    public void configureCiphersuite(IKEv1Ciphersuite ciphersuite) {
        ciphersuite.setKeylength(this);
    }

}
