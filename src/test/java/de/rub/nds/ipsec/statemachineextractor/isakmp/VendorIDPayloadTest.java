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
public class VendorIDPayloadTest {

    /**
     * Test of writeBytes method, of class VendorIDPayload.
     */
    @Test
    public void testWriteBytesDPD() {
        VendorIDPayload instance = VendorIDPayload.DeadPeerDetection;
        byte[] expResult = hexDumpToByteArray("00000014afcad71368a1f1c96b8696fc77570100");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of writeBytes method, of class VendorIDPayload.
     */
    @Test
    public void testWriteBytesXAUTH() {
        VendorIDPayload instance = VendorIDPayload.XAUTH;
        byte[] expResult = hexDumpToByteArray("0000000c09002689dfd6b712");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of writeBytes method, of class VendorIDPayload.
     */
    @Test
    public void testWriteBytesCiscoUnity10() {
        VendorIDPayload instance = VendorIDPayload.CiscoUnity10;
        byte[] expResult = hexDumpToByteArray("0000001412f5f28c457168a9702d9fe274cc0100");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of fromStream method, of class VendorIDPayload.
     */
    @Test
    public void testFromStream() throws Exception {
        VendorIDPayload origInstance = VendorIDPayload.CiscoUnity10;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        origInstance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(result);
        VendorIDPayload newInstance = VendorIDPayload.fromStream(bais);
        assertArrayEquals(origInstance.getVendorID(), newInstance.getVendorID());
        assertEquals(0, bais.available());
    }
}
