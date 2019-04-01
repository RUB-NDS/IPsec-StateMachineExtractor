/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IdentificationPayloadTest {

    /**
     * Test of setPort method, of class IdentificationPayload.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSetPort() {
        byte[] port = new byte[]{0x01, 0x02, 0x03};
        IdentificationPayload instance = new IdentificationPayload();
        instance.setPort(port);
    }

    /**
     * Test of writeBytes method, of class IdentificationPayload.
     */
    @Test
    public void testWriteBytes() {
        IdentificationPayload instance = new IdentificationPayload();
        instance.setIdType(IDTypeEnum.ID_IPV4_ADDR);
        instance.setIdentificationData(new byte[]{10, 11, 12, 13});
        byte[] expResult = new byte[]{0x00, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }

}