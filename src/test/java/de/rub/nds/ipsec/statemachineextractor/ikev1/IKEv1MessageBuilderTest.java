/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ikev1;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;
import static de.rub.nds.ipsec.statemachineextractor.ikev1.ISAKMPMessageTest.getTestIKEv1MainModeSecurityAssociationMessage;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1MessageBuilderTest {
    
    /**
     * Test of fromByteArray method, of class IKEv1MessageBuilder.
     */
    @Test
    public void testFromByteArray() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        getTestIKEv1MainModeSecurityAssociationMessage().writeBytes(baos);
        ISAKMPMessage instance = IKEv1MessageBuilder.fromByteArray(baos.toByteArray());
        assertEquals(1, instance.getPayloads().size());
    }
    
}
