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
public class NoncePayloadTest {

    private static final String TESTDATA = "7df2840825136579ffc4d39ab4b7f6f5a0"
            + "e174b8a638cc6eecf219b7b0358c4b947846a13e30d8566ea2ae0f5b99512aa"
            + "047190331ce7421a860d5e213e6fe8d24d6c591f3c3c8d33d9db14dc08dc0ba"
            + "741185021990eac800a27369160a356b12e40c1b2ec6e3fb880ee3d0e48d1f6"
            + "f21edf77021a7436dab82eace11f5ef443d2eeca8e301c3f84a1ffaac89a770"
            + "7699b99766dc55f600ae906875e8b2005c2ed3cded6a8f3d93342caa3befc6a"
            + "ca870a29d944dda4266127f6d537c417f4abd93053d9644dc7e7010c34952c1"
            + "d6dd6760e345c3f9d5545712b967a25c588a4be0d27178d92ef1f0075bdb87d"
            + "971dc046092d908b8d6b9850b7f7fdffdda95";

    public static NoncePayload getTestNoncePayload() {
        NoncePayload instance = new NoncePayload();
        instance.setNonceData(hexDumpToByteArray(TESTDATA));
        return instance;
    }

    /**
     * Test of writeBytes method, of class NoncePayload.
     */
    @Test
    public void testWriteBytes() {
        NoncePayload instance = getTestNoncePayload();
        byte[] expResult = hexDumpToByteArray("00000104" + TESTDATA);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of fromStream method, of class NoncePayload.
     */
    @Test
    public void testFromStream() throws Exception {
        NoncePayload origInstance = getTestNoncePayload();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        origInstance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(result);
        NoncePayload newInstance = NoncePayload.fromStream(bais);
        assertArrayEquals(origInstance.getNonceData(), newInstance.getNonceData());
    }
}
