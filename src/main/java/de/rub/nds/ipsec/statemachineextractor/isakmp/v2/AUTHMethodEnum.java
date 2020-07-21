/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp.v2;

import de.rub.nds.ipsec.statemachineextractor.ByteValueEnum;
import java.util.HashMap;
import java.util.Map;

/**
 * Identification Type Values as per RFC2407 Section 4.6.2.1.
 *
 * @see https://tools.ietf.org/html/rfc2407#section-4.6.2.1
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum AUTHMethodEnum implements ByteValueEnum {

    PKCS1((byte) 1),
    PSK((byte) 2),
    DSS((byte) 3);

    private final byte value;

    private AUTHMethodEnum(byte value) {
        this.value = value;
    }

    @Override
    public byte getValue() {
        return value;
    }
    
    // Reverse-lookup map
    private static final Map<Byte, AUTHMethodEnum> lookup = new HashMap<Byte, AUTHMethodEnum>();

    static {
        for (AUTHMethodEnum type : AUTHMethodEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }
    
    public static AUTHMethodEnum get(byte value) {
        return lookup.get(value);
    }

}
