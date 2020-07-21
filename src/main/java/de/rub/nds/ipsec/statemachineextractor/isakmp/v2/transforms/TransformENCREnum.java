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
public enum TransformENCREnum implements ByteValueEnum {
    AES_CBC((byte) 12, ProtocolTransformIDEnum.IKEV2_ENC_AES_CBC);

    private final byte value;
    private final ProtocolTransformIDEnum protocolTransformIDEnum;

    private TransformENCREnum(byte value, ProtocolTransformIDEnum protocolTransformIDEnum) {
        this.value = value;
        this.protocolTransformIDEnum = protocolTransformIDEnum;
    }
    
    public ProtocolTransformIDEnum toProtocolTransformIDEnum() {
        return protocolTransformIDEnum;
    }
    
    public String cipherJCEName() {
        switch (this) {
            case AES_CBC:
                return "AES";
        }
        throw new UnsupportedOperationException("Impossible unless you extend the enum!");
    }
    
    public String modeOfOperationJCEName() {
        return "CBC"; // it's as simple as that ¯\_(ツ)_/¯
    }

    @Override
    public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, TransformENCREnum> lookup = new HashMap<Byte, TransformENCREnum>();

    static {
        for (TransformENCREnum type : TransformENCREnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static TransformENCREnum get(byte value) {
        return lookup.get(value);
    }
}
