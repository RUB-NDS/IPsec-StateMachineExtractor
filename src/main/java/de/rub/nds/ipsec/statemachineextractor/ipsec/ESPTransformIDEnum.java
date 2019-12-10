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
public enum ESPTransformIDEnum implements ByteValueEnum {
    RESERVED((byte) 0, ProtocolTransformIDEnum.ESP_RESERVED, 0),
    DES_IV64((byte) 1, ProtocolTransformIDEnum.ESP_DES_IV64, 8),
    DES((byte) 2, ProtocolTransformIDEnum.ESP_DES, 8),
    TrippleDES((byte) 3, ProtocolTransformIDEnum.ESP_3DES, 24),
    RC5((byte) 4, ProtocolTransformIDEnum.ESP_RC5, 0),
    IDEA((byte) 5, ProtocolTransformIDEnum.ESP_IDEA, 16),
    CAST((byte) 6, ProtocolTransformIDEnum.ESP_CAST, 0),
    BLOWFISH((byte) 7, ProtocolTransformIDEnum.ESP_BLOWFISH, 0),
    TrippleIDEA((byte) 8, ProtocolTransformIDEnum.ESP_3IDEA, 48),
    DES_IV32((byte) 9, ProtocolTransformIDEnum.ESP_DES_IV32, 8),
    RC4((byte) 10, ProtocolTransformIDEnum.ESP_RC4, 0),
    NULL((byte) 11, ProtocolTransformIDEnum.ESP_NULL, 0),
    AES((byte) 12, ProtocolTransformIDEnum.ESP_AES, 0);

    private final byte value;
    private final int keySize;
    private final ProtocolTransformIDEnum protocolTransformIDEnum;

    private ESPTransformIDEnum(byte value, ProtocolTransformIDEnum protocolTransformIDEnum, int keySize) {
        this.value = value;
        this.protocolTransformIDEnum = protocolTransformIDEnum;
        this.keySize = keySize;
    }

    public int getKeySize() {
        return keySize;
    }

    public boolean isIsFixedKeySize() {
        return keySize != 0;
    }

    @Override
    public byte getValue() {
        return value;
    }

    public ProtocolTransformIDEnum toProtocolTransformIDEnum() {
        return protocolTransformIDEnum;
    }

    public String cipherJCEName() {
        switch (this) {
            case DES:
            case DES_IV32:
            case DES_IV64:
                return "DES";
            case BLOWFISH:
                return "Blowfish";
            case RC5:
                return "RC5-64";
            case TrippleDES:
                return "DESede";
            case AES:
                return "AES";
        }
        throw new UnsupportedOperationException("Not supported yet!");
    }

    public String modeOfOperationJCEName() {
        return "CBC"; // it's as simple as that ¯\_(ツ)_/¯
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
