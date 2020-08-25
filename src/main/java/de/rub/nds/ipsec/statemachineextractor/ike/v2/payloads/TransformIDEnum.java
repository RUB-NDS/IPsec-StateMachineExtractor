/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.payloads;

import de.rub.nds.ipsec.statemachineextractor.ByteValueEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEDHGroupEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Benjamin Koltermann <benjamin.koltermann at ruhr-uni-bochum.de>
 */
public enum TransformIDEnum implements ByteValueEnum {
    ENCR_AES_CBC((byte) 12),
    PRF_HMAC_SHA1((byte) 2),
    AUTH_HMAC_SHA1_96((byte) 2),
    DH_1024_MODP((byte) 2, IKEDHGroupEnum.GROUP2_1024);

    private final byte value;
    private IKEDHGroupEnum group = null;

    private TransformIDEnum(byte value) {
        this.value = value;
    }

    private TransformIDEnum(byte value, IKEDHGroupEnum group) {
        this.value = value;
        this.group = group;
    }

    public IKEDHGroupEnum getDHGroupParameters() {
        if (group != null) {
            return group;
        }
        return null;
    }

    @Override
    public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, TransformIDEnum> lookup = new HashMap<Byte, TransformIDEnum>();

    static {
        for (TransformIDEnum type : TransformIDEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static TransformIDEnum get(byte value) {
        return lookup.get(value);
    }
}
