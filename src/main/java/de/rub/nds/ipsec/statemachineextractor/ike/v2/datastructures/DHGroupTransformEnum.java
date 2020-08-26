/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ByteValueEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.DHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Benjamin Koltermann <benjamin.koltermann at ruhr-uni-bochum.de>
 */
public enum DHGroupTransformEnum implements ByteValueEnum {
    GROUP2_1024((byte) 2, DHGroupEnum.GROUP2_1024, ProtocolTransformIDEnum.IKEV2_DH_1024_MODP);

    private final byte value;
    private final DHGroupEnum group;
    private final ProtocolTransformIDEnum protocolTransformIDEnum;

    private DHGroupTransformEnum(byte value, DHGroupEnum group, ProtocolTransformIDEnum protocolTransformIDEnum) {
        this.value = value;
        this.group = group;
        this.protocolTransformIDEnum = protocolTransformIDEnum;
    }

    public DHGroupEnum getDHGroupParameters() {
        if (group != null) {
            return group;
        }
        return null;
    }

    public ProtocolTransformIDEnum toProtocolTransformIDEnum() {
        return protocolTransformIDEnum;
    }

    @Override
    public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, DHGroupTransformEnum> lookup = new HashMap<Byte, DHGroupTransformEnum>();

    static {
        for (DHGroupTransformEnum type : DHGroupTransformEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static DHGroupTransformEnum get(byte value) {
        return lookup.get(value);
    }
}
