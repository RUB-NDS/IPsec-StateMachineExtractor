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
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum ESPTransformIDEnum implements ByteValueEnum {
    RESERVED((byte) 0, ProtocolTransformIDEnum.ESP_RESERVED, true),
    DES_IV64((byte) 1, ProtocolTransformIDEnum.ESP_DES_IV64, true),
    DES((byte) 2, ProtocolTransformIDEnum.ESP_DES, true),
    TrippleDES((byte) 3, ProtocolTransformIDEnum.ESP_3DES, true),
    RC5((byte) 4, ProtocolTransformIDEnum.ESP_RC5, false),
    IDEA((byte) 5, ProtocolTransformIDEnum.ESP_IDEA, true),
    CAST((byte) 6, ProtocolTransformIDEnum.ESP_CAST, false),
    BLOWFISH((byte) 7, ProtocolTransformIDEnum.ESP_BLOWFISH, false),
    TrippleIDEA((byte) 8, ProtocolTransformIDEnum.ESP_3IDEA, true),
    DES_IV32((byte) 9, ProtocolTransformIDEnum.ESP_DES_IV32, true),
    RC4((byte) 10, ProtocolTransformIDEnum.ESP_RC4, false),
    NULL((byte) 11, ProtocolTransformIDEnum.ESP_NULL, true),
    AES((byte) 12, ProtocolTransformIDEnum.ESP_AES, false);

    private final byte value;
    private final ProtocolTransformIDEnum protocolTransformIDEnum;
    private final boolean isFixedKeySize;

    private ESPTransformIDEnum(byte value, ProtocolTransformIDEnum protocolTransformIDEnum, boolean isFixedKeySize) {
        this.value = value;
        this.protocolTransformIDEnum = protocolTransformIDEnum;
        this.isFixedKeySize = isFixedKeySize;
    }
    
    public boolean isIsFixedKeySize() {
        return isFixedKeySize;
    }

    @Override
    public byte getValue() {
        return value;
    }

    public ProtocolTransformIDEnum toProtocolTransformIDEnum() {
        return protocolTransformIDEnum;
    }

    // Reverse-lookup map
    private static final Map<Byte, ESPTransformIDEnum> lookup = new HashMap<Byte, ESPTransformIDEnum>();

    static {
        for (ESPTransformIDEnum type : ESPTransformIDEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static ESPTransformIDEnum get(byte value) {
        return lookup.get(value);
    }
}
