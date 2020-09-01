/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2ParsingException;
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
public final class IKEv2AttributeFactory {

    private IKEv2AttributeFactory() {

    }

    // Reverse-lookup map
    private static final Map<Integer, IKEv2Attribute> LOOKUP = new HashMap<>();

    public static IKEv2Attribute fromStream(ByteArrayInputStream bais) throws IKEv2ParsingException {
        bais.mark(0);
        int value;
        try {
            value = ByteBuffer.wrap(read4ByteFromStream(bais)).getInt();
        } catch (IOException ex) {
            throw new IKEv2ParsingException(ex);
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
            throw new UnsupportedOperationException("Not supported yet.");
        } else {
            IKEv2Attribute dummy;
            switch (formatType) {
                // Intialize the attributes and fill the LOOKUP hashmap
                case KeyLengthAttributeEnum.FORMAT_TYPE:
                    dummy = KeyLengthAttributeEnum.L128;
                    return LOOKUP.get(value);
            }
        }
        throw new IKEv2ParsingException("Encountered unknown IKEv2 attribute: " + String.format("0x%08x", value));
    }

    static void register(IKEv2Attribute attr, int value) {
        LOOKUP.put(value, attr);
    }
}
