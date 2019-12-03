/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ByteValueEnum;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum ExchangeTypeEnum implements ByteValueEnum {

    NONE((byte) 0),
    Base((byte) 1),
    IdentityProtection((byte) 2),
    AuthenticationOnly((byte) 3),
    Aggressive((byte) 4),
    Informational((byte) 5),
    QuickMode((byte) 32),
    NewGroupMode((byte) 33);

    private final byte value;

    private ExchangeTypeEnum(byte value) {
        this.value = value;
    }

    @Override
    public byte getValue() {
        return value;
    }

    // Reverse-lookup map
    private static final Map<Byte, ExchangeTypeEnum> lookup = new HashMap<Byte, ExchangeTypeEnum>();

    static {
        for (ExchangeTypeEnum type : ExchangeTypeEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }

    public static ExchangeTypeEnum get(byte value) {
        return lookup.get(value);
    }

}
