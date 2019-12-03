/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec;

import de.rub.nds.ipsec.statemachineextractor.ByteValueEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum AHTransformIDEnum implements ByteValueEnum {
    RESERVED0((byte) 0, ProtocolTransformIDEnum.AH_RESERVED0),
    RESERVED1((byte) 1, ProtocolTransformIDEnum.AH_RESERVED1),
    MD5((byte) 2, ProtocolTransformIDEnum.AH_MD5),
    SHA((byte) 3, ProtocolTransformIDEnum.AH_SHA),
    DES((byte) 4, ProtocolTransformIDEnum.AH_DES);

    private final byte value;
    private final ProtocolTransformIDEnum protocolTransformIDEnum;

    private AHTransformIDEnum(byte value, ProtocolTransformIDEnum protocolTransformIDEnum) {
        this.value = value;
        this.protocolTransformIDEnum = protocolTransformIDEnum;
    }

    @Override
    public byte getValue() {
        return value;
    }

    public ProtocolTransformIDEnum toProtocolTransformIDEnum() {
        return protocolTransformIDEnum;
    }

    // Reverse-lookup map
    private static final Map<Byte, AHTransformIDEnum> lookup = new HashMap<Byte, AHTransformIDEnum>();

    static {
        for (AHTransformIDEnum type : AHTransformIDEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static AHTransformIDEnum get(byte value) {
        return lookup.get(value);
    }
}
