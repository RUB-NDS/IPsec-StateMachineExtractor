/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec.attributes;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IPsecAttributeFactory {

    private IPsecAttributeFactory() {

    }

    // Reverse-lookup map
    private static final Map<Integer, IPsecAttribute> LOOKUP = new HashMap<>();

    public static IPsecAttribute fromInt(int value) throws ISAKMPParsingException {
        if (LOOKUP.containsKey(value)) {
            return LOOKUP.get(value);
        }
        IPsecAttribute att;
        int formatType = value >>> 16;
        switch (formatType) {
            // Intialize the attributes and fill the LOOKUP hashmap
            case AuthenticationAlgorithmAttributeEnum.FORMAT_TYPE:
                att = AuthenticationAlgorithmAttributeEnum.RESERVED;
                return LOOKUP.get(value);
            case EncapsulationModeAttributeEnum.FORMAT_TYPE:
                att = EncapsulationModeAttributeEnum.RESERVED;
                return LOOKUP.get(value);
            case KeyLengthAttributeEnum.FORMAT_TYPE:
                att = KeyLengthAttributeEnum.L128;
                return LOOKUP.get(value);
            case SALifeTypeAttributeEnum.FORMAT_TYPE:
                att = SALifeTypeAttributeEnum.RESERVED;
                return LOOKUP.get(value);
            case SALifeDurationAttribute.FORMAT_TYPE:
                return SALifeDurationAttribute.generate(value & 0xFFFF);
        }
        throw new ISAKMPParsingException("Encountered unknown attribute.");
    }

    static void register(IPsecAttribute attr, int value) {
        LOOKUP.put(value, attr);
    }
}
