/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
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
public enum PayloadTypeEnum implements ByteValueEnum {

    NONE((byte) 0),
    SecurityAssociation((byte) 1),
    Proposal((byte) 2),
    Transform((byte) 3),
    KeyExchange((byte) 4),
    Identification((byte) 5),
    Certificate((byte) 6),
    CertificateRequest((byte) 7),
    Hash((byte) 8),
    Signature((byte) 9),
    Nonce((byte) 10),
    Notification((byte) 11),
    Delete((byte) 12),
    VendorID((byte) 13),
	/**
	 * Here begins IKEv2
	 */
	SecurityAssociationv2((byte) 33),
	KeyExchangev2((byte) 34),
	Noncev2((byte) 40),
	Notify((byte) 41);

    private final byte value;

    private PayloadTypeEnum(byte value) {
        this.value = value;
    }

    @Override
    public byte getValue() {
        return value;
    }
    
    // Reverse-lookup map
    private static final Map<Byte, PayloadTypeEnum> lookup = new HashMap<Byte, PayloadTypeEnum>();

    static {
        for (PayloadTypeEnum type : PayloadTypeEnum.values()) {
            lookup.put(type.getValue(), type);
        }
    }
    
    public static PayloadTypeEnum get(byte value) {
        return lookup.get(value);
    }

}
