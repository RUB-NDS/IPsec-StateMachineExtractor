/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ByteValueEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum ProtocolIDEnum implements ByteValueEnum {
    RESERVED((byte) 0),
    ISAKMP((byte) 1),
    IPSEC_AH((byte) 2),
    IPSEC_ESP((byte) 3),
    IPCOMP((byte) 4);

    private final byte value;

    private ProtocolIDEnum(byte value) {
        this.value = value;
    }

    @Override
    public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, ProtocolIDEnum> lookup = new HashMap<Byte, ProtocolIDEnum>();

    static {
        for (ProtocolIDEnum type : ProtocolIDEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static ProtocolIDEnum get(byte value) {
        return lookup.get(value);
    }
}
