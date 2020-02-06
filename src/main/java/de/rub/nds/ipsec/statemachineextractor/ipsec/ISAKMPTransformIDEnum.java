/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
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
public enum ISAKMPTransformIDEnum implements ByteValueEnum {
    RESERVED((byte) 0, ProtocolTransformIDEnum.ISAKMP_RESERVED),
    KEY_IKE((byte) 1, ProtocolTransformIDEnum.ISAKMP_KEY_IKE);

    private final byte value;
    private final ProtocolTransformIDEnum protocolTransformIDEnum;

    private ISAKMPTransformIDEnum(byte value, ProtocolTransformIDEnum protocolTransformIDEnum) {
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
    private static final Map<Byte, ISAKMPTransformIDEnum> lookup = new HashMap<Byte, ISAKMPTransformIDEnum>();

    static {
        for (ISAKMPTransformIDEnum type : ISAKMPTransformIDEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static ISAKMPTransformIDEnum get(byte value) {
        return lookup.get(value);
    }
}
