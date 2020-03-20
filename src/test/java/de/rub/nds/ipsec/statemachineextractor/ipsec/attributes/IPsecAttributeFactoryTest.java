/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ipsec.attributes;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IPsecAttributeFactoryTest {

    /**
     * Test lazy loading.
     */
    @Test
    public void testFromInt() throws Exception {
        IPsecAttribute result = IPsecAttributeFactory.fromInt(0x80010001);
        assertEquals("SECONDS", result.toString());
    }

}
