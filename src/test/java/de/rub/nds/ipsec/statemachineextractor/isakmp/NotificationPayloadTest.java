/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import static de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper.hexDumpToByteArray;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class NotificationPayloadTest {
    
    /**
     * Test of setSpi method, of class NotificationPayload.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSetSpi() {
        byte[] spi = new byte[17];
        NotificationPayload instance = new NotificationPayload();
        instance.setSpi(spi);
    }

    /**
     * Test of writeBytes method, of class NotificationPayload.
     */
    @Test
    public void testWriteBytes() {
        NotificationPayload instance = new NotificationPayload();
        instance.setNotifyMessageType(NotifyMessageTypeEnum.PayloadMalformed);
        byte[] expResult = hexDumpToByteArray("0000000c0000000101000010");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of fromStream method, of class NotificationPayload.
     */
    @Test
    public void testFromStreamNoNotificationData() throws Exception {
        NotificationPayload origInstance = new NotificationPayload();
        origInstance.setNotifyMessageType(NotifyMessageTypeEnum.PayloadMalformed);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        origInstance.writeBytes(baos);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        NotificationPayload newInstance = NotificationPayload.fromStream(bais);
        assertArrayEquals(origInstance.getSpi(), newInstance.getSpi());
        assertArrayEquals(origInstance.getNotificationData(), newInstance.getNotificationData());
        assertEquals(origInstance.getDomainOfInterpretation(), newInstance.getDomainOfInterpretation());
        assertEquals(origInstance.getNotifyMessageType(), newInstance.getNotifyMessageType());
        assertEquals(origInstance.getProtocolID(), newInstance.getProtocolID());
        assertEquals(0, bais.available());
    }
    
    /**
     * Test of fromStream method, of class NotificationPayload.
     */
    @Test
    public void testFromStreamWithNotificationData() throws Exception {
        NotificationPayload origInstance = new NotificationPayload();
        origInstance.setNotifyMessageType(NotifyMessageTypeEnum.Connected);
        origInstance.setNotificationData(new byte[]{0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x1a});
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        origInstance.writeBytes(baos);
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        NotificationPayload newInstance = NotificationPayload.fromStream(bais);
        assertArrayEquals(origInstance.getSpi(), newInstance.getSpi());
        assertArrayEquals(origInstance.getNotificationData(), newInstance.getNotificationData());
        assertEquals(origInstance.getDomainOfInterpretation(), newInstance.getDomainOfInterpretation());
        assertEquals(origInstance.getNotifyMessageType(), newInstance.getNotifyMessageType());
        assertEquals(origInstance.getProtocolID(), newInstance.getProtocolID());
        assertEquals(0, bais.available());
    }
    
}
