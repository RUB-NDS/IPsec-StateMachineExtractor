/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.ipsec.statemachineextractor.ikev1;

import static de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayloadTest.getTestSecurityAssociationPayload;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1MainModeSecurityAssociationMessageTest {

    /**
     * Test of getBytes method, of class
     * IKEv1MainModeSecurityAssociationMessage. This message was extracted from
     * a Wireshark dump.
     */
    @Test
    public void testGetBytes() {
        IKEv1MainModeSecurityAssociationMessage instance = new IKEv1MainModeSecurityAssociationMessage();
        instance.setInitiatorCookie(new byte[]{0x63, 0x31, 0x32, 0x41, 0x4a, 0x48, 0x4e, 0x78});
        instance.addPayload(getTestSecurityAssociationPayload());
        byte[] expResult = new byte[]{
            0x63, 0x31, 0x32, 0x41, 0x4a, 0x48, 0x4e, 0x78,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x38,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x2c, 0x01, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x00,
            -128, 0x01, 0x00, 0x07, -128, 0x0e, 0x00, -128,
            -128, 0x02, 0x00, 0x02, -128, 0x04, 0x00, 0x05,
            -128, 0x03, 0x00, 0x04, -128, 0x0b, 0x00, 0x01,
            -128, 0x0c, 0x70, -128
        };
        assertArrayEquals(expResult, instance.getBytes());
    }

}
