/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SecurityAssociationPayload;
import static de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ProposalPayloadTest.getTestProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SecurityAssociationPayloadTest {

    public static SecurityAssociationPayload getTestSecurityAssociationPayload() {
        SecurityAssociationPayload instance = new SecurityAssociationPayload();
        instance.setIdentityOnlyFlag(true);
        instance.addProposalPayload(getTestProposalPayload());
        return instance;
    }

    /**
     * Test of writeBytes method, of class SecurityAssociationPayload.
     */
    @Test
    public void testWriteBytes() {
        SecurityAssociationPayload instance = getTestSecurityAssociationPayload();
        byte[] expResult = new byte[]{
            0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2c,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24,
            0x00, 0x01, 0x00, 0x00, -128, 0x01, 0x00, 0x07,
            -128, 0x0e, 0x00, -128, -128, 0x02, 0x00, 0x02,
            -128, 0x04, 0x00, 0x05, -128, 0x03, 0x00, 0x04,
            -128, 0x0b, 0x00, 0x01, -128, 0x0c, 0x70, -128
        };
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of fromStream method, of class SecurityAssociationPayload.
     */
    @Test
    public void testFromStream() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        getTestSecurityAssociationPayload().writeBytes(baos);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        SecurityAssociationPayload instance = SecurityAssociationPayload.fromStream(bais);
        assertEquals(0, bais.available());
        assertArrayEquals(DatatypeHelper.intTo4ByteArray(1), instance.getSituation());
        assertEquals(1, instance.getDomainOfInterpretation());
    }
}
