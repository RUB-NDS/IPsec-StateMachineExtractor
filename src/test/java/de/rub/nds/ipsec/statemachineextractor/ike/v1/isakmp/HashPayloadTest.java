/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class HashPayloadTest {
    
    /**
     * Test of fromStream method, of class HashPayload.
     */
    @Test
    public void testFromStream() throws Exception {
        // Dirty, but it's binary data anyway...
        VendorIDPayload origInstance = VendorIDPayload.DeadPeerDetection;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        origInstance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(result);
        HashPayload newInstance = HashPayload.fromStream(bais);
        assertArrayEquals(origInstance.getBinaryData(), newInstance.getHashData());
        assertEquals(0, bais.available());
    }
    
    /**
     * Test of fromStream method, of class HashPayload.
     */
    @Test(expected=ISAKMPParsingException.class)
    public void testFromStreamLengthTooShort() throws Exception {
        VendorIDPayload origInstance = VendorIDPayload.DeadPeerDetection;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        origInstance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        result[3] = 3;
        ByteArrayInputStream bais = new ByteArrayInputStream(result);
        HashPayload newInstance = HashPayload.fromStream(bais);
    }
}
