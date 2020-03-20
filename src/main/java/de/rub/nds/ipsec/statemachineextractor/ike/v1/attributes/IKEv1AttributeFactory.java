/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IKEv1AttributeFactory {

    private IKEv1AttributeFactory() {

    }

    // Reverse-lookup map
    private static final Map<Integer, IKEv1Attribute> LOOKUP = new HashMap<>();

    public static IKEv1Attribute fromInt(int value) throws ISAKMPParsingException {
        if (LOOKUP.containsKey(value)) {
            return LOOKUP.get(value);
        }
        IKEv1Attribute att;
        int formatType = value >>> 16;
        switch (formatType) {
            // Intialize the attributes and fill the LOOKUP hashmap
            case AuthAttributeEnum.FORMAT_TYPE:
                att = AuthAttributeEnum.PSK;
                return LOOKUP.get(value);
            case CipherAttributeEnum.FORMAT_TYPE:
                att = CipherAttributeEnum.AES_CBC;
                return LOOKUP.get(value);
            case DHGroupAttributeEnum.FORMAT_TYPE:
                att = DHGroupAttributeEnum.GROUP1;
                return LOOKUP.get(value);
            case HashAttributeEnum.FORMAT_TYPE:
                att = HashAttributeEnum.MD5;
                return LOOKUP.get(value);
            case KeyLengthAttributeEnum.FORMAT_TYPE:
                att = KeyLengthAttributeEnum.L128;
                return LOOKUP.get(value);
            case LifeTypeAttributeEnum.FORMAT_TYPE:
                att = LifeTypeAttributeEnum.SECONDS;
                return LOOKUP.get(value);
            case LifeDurationAttribute.FORMAT_TYPE:
                return LifeDurationAttribute.generate(value & 0xFFFF);
        }
        throw new ISAKMPParsingException("Encountered unknown attribute.");
    }

    static void register(IKEv1Attribute attr, int value) {
        LOOKUP.put(value, attr);
    }
}
