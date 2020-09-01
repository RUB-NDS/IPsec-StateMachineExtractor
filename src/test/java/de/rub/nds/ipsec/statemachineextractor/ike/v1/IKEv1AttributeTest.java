/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeDurationAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPAttribute;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1AttributeTest {
    
    /**
     * Test of hashCode method, of class ISAKMPAttribute.
     */
    @Test
    public void testHashCode() {
        ISAKMPAttribute instance = LifeDurationAttribute.get(28800);
        byte[] expResult = DatatypeHelper.intTo4ByteArray(0x800c7080);
        assertArrayEquals(expResult, instance.getBytes());
    }
    
}
