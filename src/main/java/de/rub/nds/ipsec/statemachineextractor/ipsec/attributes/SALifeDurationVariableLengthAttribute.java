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
import de.rub.nds.ipsec.statemachineextractor.isakmp.VariableLengthAttribute;
import java.io.ByteArrayInputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SALifeDurationVariableLengthAttribute extends VariableLengthAttribute implements IPsecAttribute {

    protected static final short FORMAT_TYPE = 0x0002;

    public SALifeDurationVariableLengthAttribute(byte[] value) {
        super(FORMAT_TYPE, value);
    }
    
    public static SALifeDurationVariableLengthAttribute fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        SALifeDurationVariableLengthAttribute attr = new SALifeDurationVariableLengthAttribute(null);
        attr.fillFromStream(bais);
        return attr;
    }

}
