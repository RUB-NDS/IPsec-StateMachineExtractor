/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1AttributeFactoryTest {
    
   /**
     * Test lazy loading.
     */
    @Test
    public void testFromInt() throws Exception {
        byte[] bytes = DatatypeHelper.intTo4ByteArray(0x800b0001);
        IKEv1Attribute result = IKEv1AttributeFactory.fromStream(new ByteArrayInputStream(bytes));
        assertEquals("SECONDS", result.toString());
    }
    
}
