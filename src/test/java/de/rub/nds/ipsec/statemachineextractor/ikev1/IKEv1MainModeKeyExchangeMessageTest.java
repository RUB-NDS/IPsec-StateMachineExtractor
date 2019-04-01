/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ikev1;

import de.rub.nds.ipsec.statemachineextractor.ikev1.shims.CiscoPKEIdentificationPayloadTest;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayloadTest;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NoncePayloadTest;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.VendorIDPayload;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1MainModeKeyExchangeMessageTest {
    
    private static final String TESTDATA = "633132414a484e78a7f9df47256e976b04"
            + "10020000000000000002fc050000c4080b8f6b6883a2b694d24ce8a9453b760"
            + "2bd3d5360b29742a1ab8b9b8595fe38c8313381a26f0c0ba5cc9e5f7b7912b5"
            + "d4e34b495cc17b282d2e805dabedaa797262b677631fecba270112521264e81"
            + "3b9308f8c97d0a385a73674a1c90b69fb1ba5f3c2eae3ff255d244ee69b02fb"
            + "38ba6087cbc815b1bb7237dc6dc03cc43d5dd1ff2faf613b7165f93ebc8da33"
            + "eb071f8d333edbc0ea0a85a8e15ee3eabe48b85b32a1e570abda71013bff820"
            + "ccb190c5140ffbafa273e795cb4b77f287a20a00010450e6b66c8dc322e8630"
            + "66bcd77fa1986a67c3de6b131d69105fb8b71127c7ba96edf64b5f5727e6503"
            + "53b3f3ec573247a7b437db068376d9f6d53d854b38cfce5067877857f597de2"
            + "68cb55722ce271bb3f92e4c7e8e153970a53369d570043294d83c4a3517dd09"
            + "150b54e51e09a479e66d74651c1c970f8c48e5a1a58c10881136a77cb354037"
            + "c3f19dac9b504582299e6b8314bb46d58f70d0b516e7f8219d8f87388767e3e"
            + "7f1c8e58bd9ed4892c54acb20e9b9e6d02d1f969274b19d64068ee3f6e50327"
            + "6ed6f6652ee6cf4ec782b4b1dad3ce13a04e6664e038f842ce86d3337de94ca"
            + "195ec95fc6731e48bbc02258cc6199214efd147701302d9bb61d0d0001047df"
            + "2840825136579ffc4d39ab4b7f6f5a0e174b8a638cc6eecf219b7b0358c4b94"
            + "7846a13e30d8566ea2ae0f5b99512aa047190331ce7421a860d5e213e6fe8d2"
            + "4d6c591f3c3c8d33d9db14dc08dc0ba741185021990eac800a27369160a356b"
            + "12e40c1b2ec6e3fb880ee3d0e48d1f6f21edf77021a7436dab82eace11f5ef4"
            + "43d2eeca8e301c3f84a1ffaac89a7707699b99766dc55f600ae906875e8b200"
            + "5c2ed3cded6a8f3d93342caa3befc6aca870a29d944dda4266127f6d537c417"
            + "f4abd93053d9644dc7e7010c34952c1d6dd6760e345c3f9d5545712b967a25c"
            + "588a4be0d27178d92ef1f0075bdb87d971dc046092d908b8d6b9850b7f7fdff"
            + "dda9500000014afcad71368a1f1c96b8696fc77570100";
    
    /**
     * Test of addPayload method, of class IKEv1MainModeKeyExchangeMessage.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testAddPayload() {
        ISAKMPPayload payload = new SecurityAssociationPayload();
        IKEv1MainModeKeyExchangeMessage instance = new IKEv1MainModeKeyExchangeMessage();
        instance.addPayload(payload);
    }
    
    /**
     * Test of addPayload method, of class IKEv1MainModeKeyExchangeMessage.
     */
    @Test
    public void testFullMessage() {
        IKEv1MainModeKeyExchangeMessage instance = new IKEv1MainModeKeyExchangeMessage();
        instance.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("633132414a484e78"));
        instance.setResponderCookie(DatatypeHelper.hexDumpToByteArray("a7f9df47256e976b"));
        instance.addPayload(KeyExchangePayloadTest.getTestKeyExchangePayload());
        instance.addPayload(CiscoPKEIdentificationPayloadTest.getTestCiscoPKEIdentificationPayload());
        instance.addPayload(NoncePayloadTest.getTestNoncePayload());
        instance.addPayload(VendorIDPayload.DeadPeerDetection);
        byte[] expResult = DatatypeHelper.hexDumpToByteArray(TESTDATA);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
}
