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
        if ((value >>> 16) == SALifeDurationAttribute.FORMAT_TYPE) { // it's a SALifeDurationAttribute
            return SALifeDurationAttribute.generate(value & 0xFFFF);
        }
        throw new ISAKMPParsingException("Encountered unknown attribute.");
    }
    
    static void register(IPsecAttribute attr, int value) {
        LOOKUP.put(value, attr);
    }
}
