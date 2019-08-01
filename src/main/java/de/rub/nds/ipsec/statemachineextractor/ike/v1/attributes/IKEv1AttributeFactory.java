/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
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
        if ((value >>> 16) == 0x800c) { // it's a DurationAttribute
            return DurationAttribute.generate(value & 0xFFFF);
        }
        throw new ISAKMPParsingException("Encountered unknown attribute.");
    }
    
    static void register(IKEv1Attribute attr, int value) {
        LOOKUP.put(value, attr);
    }
}
