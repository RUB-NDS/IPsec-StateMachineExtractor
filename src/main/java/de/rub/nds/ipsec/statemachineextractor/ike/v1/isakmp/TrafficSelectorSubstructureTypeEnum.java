/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ByteValueEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum TrafficSelectorSubstructureTypeEnum implements ByteValueEnum {
    TS_IPV4_ADDR_RANGE((byte) 7),
    TS_IPV6_ADDR_RANGE((byte) 8);

    private final byte value;

    private TrafficSelectorSubstructureTypeEnum(byte value) {
        this.value = value;
    }

    @Override
    public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, TrafficSelectorSubstructureTypeEnum> lookup = new HashMap<Byte, TrafficSelectorSubstructureTypeEnum>();

    static {
        for (TrafficSelectorSubstructureTypeEnum type : TrafficSelectorSubstructureTypeEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static TrafficSelectorSubstructureTypeEnum get(byte value) {
        return lookup.get(value);
    }
}
