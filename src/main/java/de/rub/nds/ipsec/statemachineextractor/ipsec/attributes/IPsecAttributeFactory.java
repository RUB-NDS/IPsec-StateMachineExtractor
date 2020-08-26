/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPParsingException;
import static de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper.read4ByteFromStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
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

    public static IPsecAttribute fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        bais.mark(0);
        int value;        
        try {
            value = ByteBuffer.wrap(read4ByteFromStream(bais)).getInt();
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        if (LOOKUP.containsKey(value)) {
            return LOOKUP.get(value);
        }
        int formatType = value >>> 16;
        if (!BigInteger.valueOf(formatType).testBit(15)) {
            /* If the most significant bit, or Attribute Format (AF), is a
             * zero (0), then the Data Attributes are of the Type/Length/Value
             * (TLV) form.  If the AF bit is a one (1), then the Data Attributes
             * are of the Type/Value form.
             */
            bais.reset();
            switch (formatType) {
                case SALifeDurationVariableLengthAttribute.FORMAT_TYPE:
                    return SALifeDurationVariableLengthAttribute.fromStream(bais);
            }
        } else {
            IPsecAttribute dummy;
            switch (formatType) {
                // Intialize the attributes and fill the LOOKUP hashmap
                case AuthenticationAlgorithmAttributeEnum.FORMAT_TYPE:
                    dummy = AuthenticationAlgorithmAttributeEnum.RESERVED;
                    return LOOKUP.get(value);
                case EncapsulationModeAttributeEnum.FORMAT_TYPE:
                    dummy = EncapsulationModeAttributeEnum.RESERVED;
                    return LOOKUP.get(value);
                case KeyLengthAttributeEnum.FORMAT_TYPE:
                    dummy = KeyLengthAttributeEnum.L128;
                    return LOOKUP.get(value);
                case SALifeTypeAttributeEnum.FORMAT_TYPE:
                    dummy = SALifeTypeAttributeEnum.RESERVED;
                    return LOOKUP.get(value);
                case SALifeDurationBasicAttribute.FORMAT_TYPE:
                    return SALifeDurationBasicAttribute.generate(value & 0xFFFF);
                case KeyLengthAttributeEnumv2.FORMAT_TYPE:
                    dummy = KeyLengthAttributeEnumv2.L128;
                	return LOOKUP.get(value);
            }
        }
        throw new ISAKMPParsingException("Encountered unknown IPsec attribute: " + String.format("0x%08x", value));
    }

    public static void register(IPsecAttribute attr, int value) {
        LOOKUP.put(value, attr);
    }
}
