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
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Benjamin Koltermann <benjamin.koltermann at ruhr-uni-bochum.de>
 */
public enum TransformPRFEnum implements ByteValueEnum {
    SHA1((byte) 2, ProtocolTransformIDEnum.IKEV2_PRF_HMAC_SHA1);

    private final byte value;
    private final ProtocolTransformIDEnum protocolTransformIDEnum;

    private TransformPRFEnum(byte value, ProtocolTransformIDEnum protocolTransformIDEnum) {
        this.value = value;
        this.protocolTransformIDEnum = protocolTransformIDEnum;
    }

    public ProtocolTransformIDEnum toProtocolTransformIDEnum() {
        return protocolTransformIDEnum;
    }

    @Override
    public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, TransformPRFEnum> lookup = new HashMap<Byte, TransformPRFEnum>();

    static {
        for (TransformPRFEnum type : TransformPRFEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static TransformPRFEnum get(byte value) {
        return lookup.get(value);
    }
}
