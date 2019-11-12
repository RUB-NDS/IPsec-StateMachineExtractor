/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
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
public enum SALifeTypeAttributeEnum implements IPsecAttribute, ISAKMPSerializable {

    RESERVED(0x80010000),
    SECONDS(0x80010001),
    KILOBYTES(0x80010002);

    private final byte[] bytes;

    private SALifeTypeAttributeEnum(int value) {
        this.bytes = DatatypeHelper.intTo4ByteArray(value);
        IPsecAttributeFactory.register(this, value);
    }

    @Override
    public byte[] getBytes() {
        return bytes.clone();
    }

}