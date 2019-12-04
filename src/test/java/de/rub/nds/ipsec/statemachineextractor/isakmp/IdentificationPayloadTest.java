/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import static org.junit.Assert.*;
import org.junit.Test;

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
        instance.setIdType(IDTypeEnum.IPV4_ADDR);
        instance.setIdentificationData(new byte[]{10, 11, 12, 13});
        byte[] expResult = new byte[]{0x00, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x0b, 0x0c, 0x0d};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of fromStream method, of class IdentificationPayload.
     */
    @Test
    public void testFromStream() throws Exception {
        IdentificationPayload origInstance = new IdentificationPayload();
        origInstance.setIdType(IDTypeEnum.IPV4_ADDR);
        origInstance.setIdentificationData(new byte[]{10, 11, 12, 13});
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        origInstance.writeBytes(baos);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        IdentificationPayload newInstance = IdentificationPayload.fromStream(bais);
        assertArrayEquals(origInstance.getIdentificationData(), newInstance.getIdentificationData());
        assertEquals(origInstance.getIdType(), newInstance.getIdType());
        assertEquals(origInstance.getProtocolID(), newInstance.getProtocolID());
        assertArrayEquals(origInstance.getPort(), newInstance.getPort());
        assertEquals(0, bais.available());
    }

}   
