/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec.attributes;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.ike.BasicIKEAttribute;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum KeyLengthAttributeEnum implements IPsecAttribute, BasicIKEAttribute {

    L128(0x80060080, 16),
    L192(0x800600C0, 24),
    L256(0x80060100, 32);

    protected static final int FORMAT_TYPE = 0x8006;
    private final byte[] bytes;
    private final int keySize;

    private KeyLengthAttributeEnum(int value, int keySize) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        this.keySize = keySize;
        IPsecAttributeFactory.register(this, value);
    }

    public int getKeySize() {
        return this.keySize;
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }
}
