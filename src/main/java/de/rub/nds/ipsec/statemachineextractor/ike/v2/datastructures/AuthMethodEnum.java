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
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Benjamin Koltermann <benjamin.koltermann at ruhr-uni-bochum.de>
 */
public enum AuthMethodEnum implements ByteValueEnum {

    PKCS1((byte) 1),
    PSK((byte) 2),
    DSS((byte) 3);

    private final byte value;

    private AuthMethodEnum(byte value) {
        this.value = value;
    }

    @Override
    public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, AuthMethodEnum> lookup = new HashMap<Byte, AuthMethodEnum>();

    static {
        for (AuthMethodEnum type : AuthMethodEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static AuthMethodEnum get(byte value) {
        return lookup.get(value);
    }

}
