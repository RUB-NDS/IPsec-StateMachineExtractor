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
 * Identification Type Values as per RFC2407 Section 4.6.2.1.
 *
 * @see https://tools.ietf.org/html/rfc2407#section-4.6.2.1
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum IDTypeEnum implements ByteValueEnum {

    RESERVED((byte) 0),
    IPV4_ADDR((byte) 1),
    FQDN((byte) 2),
    USER_FQDN((byte) 3),
    IPV4_ADDR_SUBNET((byte) 4),
    IPV6_ADDR((byte) 5),
    IPV6_ADDR_SUBNET((byte) 6),
    IPV4_ADDR_RANGE((byte) 7),
    IPV6_ADDR_RANGE((byte) 8),
    DER_ASN1_DN((byte) 9),
    DER_ASN1_GN((byte) 10),
    KEY_ID((byte) 11);

    private final byte value;

    private IDTypeEnum(byte value) {
        this.value = value;
    }

    @Override
    public byte getValue() {
        return value;
    }
    
    // Reverse-lookup map
    private static final Map<Byte, IDTypeEnum> lookup = new HashMap<Byte, IDTypeEnum>();

    static {
        for (IDTypeEnum type : IDTypeEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }
    
    public static IDTypeEnum get(byte value) {
        return lookup.get(value);
    }

}
