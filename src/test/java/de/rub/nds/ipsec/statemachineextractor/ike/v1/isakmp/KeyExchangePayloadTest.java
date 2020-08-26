/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.KeyExchangePayload;
import static de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper.hexDumpToByteArray;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class KeyExchangePayloadTest {

    private static final String TESTDATA = "080b8f6b6883a2b694d24ce8a9453b7602"
            + "bd3d5360b29742a1ab8b9b8595fe38c8313381a26f0c0ba5cc9e5f7b7912b5d"
            + "4e34b495cc17b282d2e805dabedaa797262b677631fecba270112521264e813"
            + "b9308f8c97d0a385a73674a1c90b69fb1ba5f3c2eae3ff255d244ee69b02fb3"
            + "8ba6087cbc815b1bb7237dc6dc03cc43d5dd1ff2faf613b7165f93ebc8da33e"
            + "b071f8d333edbc0ea0a85a8e15ee3eabe48b85b32a1e570abda71013bff820c"
            + "cb190c5140ffbafa273e795cb4b77f287a2";

    public static KeyExchangePayload getTestKeyExchangePayload() {
        KeyExchangePayload instance = new KeyExchangePayload();
        instance.setKeyExchangeData(hexDumpToByteArray(TESTDATA));
        return instance;
    }

    /**
     * Test of writeBytes method, of class KeyExchangePayload.
     */
    @Test
    public void testWriteBytes() {
        KeyExchangePayload instance = getTestKeyExchangePayload();
        byte[] expResult = hexDumpToByteArray("000000c4" + TESTDATA);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of fromStream method, of class KeyExchangePayload.
     */
    @Test
    public void testFromStream() throws Exception {
        KeyExchangePayload origInstance = getTestKeyExchangePayload();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        origInstance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(result);
        KeyExchangePayload newInstance = KeyExchangePayload.fromStream(bais);
        assertArrayEquals(origInstance.getKeyExchangeData(), newInstance.getKeyExchangeData());
        assertEquals(0, bais.available());
    }
}
