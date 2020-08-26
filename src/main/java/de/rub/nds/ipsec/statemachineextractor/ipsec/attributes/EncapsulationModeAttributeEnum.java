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
public enum EncapsulationModeAttributeEnum implements IPsecAttribute, BasicIKEAttribute {

    RESERVED(0x80040000),
    Tunnel(0x80040001),
    Transport(0x80040002);

    protected static final int FORMAT_TYPE = 0x8004;
    private final byte[] bytes;

    private EncapsulationModeAttributeEnum(int value) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        IPsecAttributeFactory.register(this, value);
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }
}
