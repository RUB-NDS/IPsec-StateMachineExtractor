/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp.v2.transforms;

import de.rub.nds.ipsec.statemachineextractor.ByteValueEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEDHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Benjamin Koltermann <benjamin.koltermann at ruhr-uni-bochum.de>
 */
public enum TransformDHEnum implements ByteValueEnum {
    GROUP2((byte) 2, IKEDHGroupEnum.GROUP2_1024, ProtocolTransformIDEnum.IKEV2_DH_1024_MODP);

    private final byte value;
    private final IKEDHGroupEnum group;
    private final ProtocolTransformIDEnum protocolTransformIDEnum;

    private TransformDHEnum(byte value, IKEDHGroupEnum group, ProtocolTransformIDEnum protocolTransformIDEnum) {
        this.value = value;
        this.group = group;
        this.protocolTransformIDEnum = protocolTransformIDEnum;
    }

    public IKEDHGroupEnum getDHGroupParameters() {
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
    private static final Map<Byte, TransformDHEnum> lookup = new HashMap<Byte, TransformDHEnum>();

    static {
        for (TransformDHEnum type : TransformDHEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static TransformDHEnum get(byte value) {
        return lookup.get(value);
    }
}
