/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPAttribute;
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
public final class IKEv1AttributeFactory {

    private IKEv1AttributeFactory() {

    }

    // Reverse-lookup map
    private static final Map<Integer, ISAKMPAttribute> LOOKUP = new HashMap<>();

    public static ISAKMPAttribute fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
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
//            switch (formatType) {
//                case SomeVariableLengthAttribute.FORMAT_TYPE:
//                    return SomeVariableLengthAttribute.fromStream(bais);
//            }
        } else {
            ISAKMPAttribute dummy;
            switch (formatType) {
                // Intialize the attributes and fill the LOOKUP hashmap
                case AuthAttributeEnum.FORMAT_TYPE:
                    dummy = AuthAttributeEnum.PSK;
                    return LOOKUP.get(value);
                case CipherAttributeEnum.FORMAT_TYPE:
                    dummy = CipherAttributeEnum.AES_CBC;
                    return LOOKUP.get(value);
                case DHGroupAttributeEnum.FORMAT_TYPE:
                    dummy = DHGroupAttributeEnum.GROUP1;
                    return LOOKUP.get(value);
                case HashAttributeEnum.FORMAT_TYPE:
                    dummy = HashAttributeEnum.MD5;
                    return LOOKUP.get(value);
                case KeyLengthAttributeEnum.FORMAT_TYPE:
                    dummy = KeyLengthAttributeEnum.L128;
                    return LOOKUP.get(value);
                case LifeTypeAttributeEnum.FORMAT_TYPE:
                    dummy = LifeTypeAttributeEnum.SECONDS;
                    return LOOKUP.get(value);
                case LifeDurationAttribute.FORMAT_TYPE:
                    return LifeDurationAttribute.generate(value & 0xFFFF);
            }
        }
        throw new ISAKMPParsingException("Encountered unknown IKEv1 attribute: " + String.format("0x%08x", value));
    }

    static void register(ISAKMPAttribute attr, int value) {
        LOOKUP.put(value, attr);
    }
}
