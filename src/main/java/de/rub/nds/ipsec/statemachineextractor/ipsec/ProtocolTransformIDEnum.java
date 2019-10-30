/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ByteValueEnum;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum ProtocolTransformIDEnum implements ByteValueEnum {
    ISAKMP_RESERVED((byte) 0),
    ISAKMP_KEY_IKE((byte) 1),
    AH_RESERVED0((byte) 0),
    AH_RESERVED1((byte) 1),
    AH_MD5((byte) 2),
    AH_SHA((byte) 3),
    AH_DES((byte) 4),
    ESP_RESERVED((byte) 0),
    ESP_DES_IV64((byte) 1),
    ESP_DES((byte) 2),
    ESP_3DES((byte) 3),
    ESP_RC5((byte) 4),
    ESP_IDEA((byte) 5),
    ESP_CAST((byte) 6),
    ESP_BLOWFISH((byte) 7),
    ESP_3IDEA((byte) 8),
    ESP_DES_IV32((byte) 9),
    ESP_RC4((byte) 10),
    ESP_NULL((byte) 11),
    ESP_AES((byte) 12);

    private final byte value;

private ProtocolTransformIDEnum(byte value) {
        this.value = value;
    }

    @Override
        public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, Collection<ProtocolTransformIDEnum>> lookup = new HashMap<Byte, Collection<ProtocolTransformIDEnum>>();

    static {
        for (ProtocolTransformIDEnum type : ProtocolTransformIDEnum.values()) {
            if (!lookup.containsKey(type.getValue())) {
                lookup.put(type.getValue(), new HashSet<>());
            }
            lookup.get(type.getValue()).add(type);
        }
    }

    public static ProtocolTransformIDEnum getFirstMatch(byte value) {
        return lookup.get(value).iterator().next();
    }
}
