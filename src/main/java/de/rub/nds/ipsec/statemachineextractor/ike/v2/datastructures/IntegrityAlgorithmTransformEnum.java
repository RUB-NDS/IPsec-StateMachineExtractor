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
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Benjamin Koltermann <benjamin.koltermann at ruhr-uni-bochum.de>
 */
public enum IntegrityAlgorithmTransformEnum implements ByteValueEnum {
    SHA1((byte) 2, ProtocolTransformIDEnum.IKEV2_INTEG_HMAC_SHA1_96); //SHA1_96

    private final byte value;
    private final ProtocolTransformIDEnum protocolTransformIDEnum;

    private IntegrityAlgorithmTransformEnum(byte value, ProtocolTransformIDEnum protocolTransformIDEnum) {
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
    private static final Map<Byte, IntegrityAlgorithmTransformEnum> lookup = new HashMap<Byte, IntegrityAlgorithmTransformEnum>();

    static {
        for (IntegrityAlgorithmTransformEnum type : IntegrityAlgorithmTransformEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static IntegrityAlgorithmTransformEnum get(byte value) {
        return lookup.get(value);
    }
}
