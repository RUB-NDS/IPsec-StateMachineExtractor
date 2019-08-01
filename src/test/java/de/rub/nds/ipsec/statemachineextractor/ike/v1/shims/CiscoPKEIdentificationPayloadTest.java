/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.shims;

import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import static de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper.hexDumpToByteArray;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class CiscoPKEIdentificationPayloadTest {
    
    private static final String TESTDATA = "50e6b66c8dc322e863066bcd77fa1986a6"
            + "7c3de6b131d69105fb8b71127c7ba96edf64b5f5727e650353b3f3ec573247a"
            + "7b437db068376d9f6d53d854b38cfce5067877857f597de268cb55722ce271b"
            + "b3f92e4c7e8e153970a53369d570043294d83c4a3517dd09150b54e51e09a47"
            + "9e66d74651c1c970f8c48e5a1a58c10881136a77cb354037c3f19dac9b50458"
            + "2299e6b8314bb46d58f70d0b516e7f8219d8f87388767e3e7f1c8e58bd9ed48"
            + "92c54acb20e9b9e6d02d1f969274b19d64068ee3f6e503276ed6f6652ee6cf4"
            + "ec782b4b1dad3ce13a04e6664e038f842ce86d3337de94ca195ec95fc6731e4"
            + "8bbc02258cc6199214efd147701302d9bb61d";
    
    public static CiscoPKEIdentificationPayload getTestCiscoPKEIdentificationPayload() {
        CiscoPKEIdentificationPayload instance = new CiscoPKEIdentificationPayload();
        instance.setIdentificationData(hexDumpToByteArray(TESTDATA));
        return instance;
    }
    
    /**
     * Test of writeBytes method, of class IdentificationPayloadCiscoPKE.
     */
    @Test
    public void testWriteBytes() {
        IdentificationPayload instance = getTestCiscoPKEIdentificationPayload();
        instance.setIdentificationData(DatatypeHelper.hexDumpToByteArray(TESTDATA));
        byte[] expResult = DatatypeHelper.hexDumpToByteArray("00000104" + TESTDATA);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
}
