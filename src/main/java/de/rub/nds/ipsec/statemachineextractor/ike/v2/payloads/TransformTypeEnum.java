/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.payloads;

import de.rub.nds.ipsec.statemachineextractor.ByteValueEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Benjamin Koltermann <benjamin.koltermann at ruhr-uni-bochum.de>
 */
public enum TransformTypeEnum implements ByteValueEnum {
    ENCR((byte) 1),
    PRF((byte) 2),
    INTEG((byte) 3),
    DH((byte) 4),
    ESN((byte) 5);

    private final byte value;

    private TransformTypeEnum(byte value) {
        this.value = value;
    }

    @Override
    public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, TransformTypeEnum> lookup = new HashMap<Byte, TransformTypeEnum>();

    static {
        for (TransformTypeEnum type : TransformTypeEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static TransformTypeEnum get(byte value) {
        return lookup.get(value);
    }
}
