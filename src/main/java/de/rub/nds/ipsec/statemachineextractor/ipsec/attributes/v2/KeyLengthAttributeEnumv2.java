/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.v2;

import de.rub.nds.ipsec.statemachineextractor.isakmp.BasicAttribute;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.IPsecAttribute;
import de.rub.nds.ipsec.statemachineextractor.ipsec.attributes.IPsecAttributeFactory;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum KeyLengthAttributeEnumv2 implements IPsecAttribute, BasicAttribute {

    L128(0x800e0080, 16);

    public static final int FORMAT_TYPE = 0x800e;
    private final byte[] bytes;
    private final int keySize;

    private KeyLengthAttributeEnumv2(int value, int keySize) {
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
