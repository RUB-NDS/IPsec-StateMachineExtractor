/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import static de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayloadTest.getTestSecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ISAKMPMessageTest {
    
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
    
    public static ISAKMPMessage getTestIKEv1MainModeSecurityAssociationMessage() {
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("633132414a484e78"));
        instance.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        instance.addPayload(getTestSecurityAssociationPayload());
        return instance;
    }
    
    public static ISAKMPMessage getTestIKEv1MainModeKeyExchangeMessage() {
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("633132414a484e78"));
        instance.setResponderCookie(DatatypeHelper.hexDumpToByteArray("a7f9df47256e976b"));
        instance.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        instance.addPayload(KeyExchangePayloadTest.getTestKeyExchangePayload());
        instance.addPayload(IdentificationPayloadPKETest.getTestStaticIdentificationPayloadPKE());
        instance.addPayload(NoncePayloadTest.getTestNoncePayload());
        instance.addPayload(VendorIDPayload.DeadPeerDetection);
        return instance;
    }
    
    /**
     * Test of addPayload method, of class IKEv1MainModeKeyExchangeMessage.
     */
    @Test
    public void testFullMessage() throws GeneralSecurityException, ISAKMPParsingException {
        ISAKMPMessage instance = getTestIKEv1MainModeKeyExchangeMessage();
        byte[] expResult = DatatypeHelper.hexDumpToByteArray(TESTDATA);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        instance.writeBytes(baos);
        byte[] result = baos.toByteArray();
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of getBytes method, of class
     * IKEv1MainModeSecurityAssociationMessage. This message was extracted from
     * a Wireshark dump.
     */
    @Test
    public void testGetBytesWithPayload() {
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setInitiatorCookie(new byte[]{0x63, 0x31, 0x32, 0x41, 0x4a, 0x48, 0x4e, 0x78});
        instance.setExchangeType(ExchangeTypeEnum.IdentityProtection);
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
    
    /**
     * Test of getInitiatorCookie method, of class ISAKMPMessage.
     */
    @Test
    public void testGetInitiatorCookie() {
        ISAKMPMessage instance = new ISAKMPMessage();
        byte[] result = instance.getInitiatorCookie();
        assertEquals(8, result.length);
    }

    /**
     * Test of setInitiatorCookie method, of class ISAKMPMessage.
     */
    @Test
    public void testSetInitiatorCookie() {
        byte[] initiatorCookie = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D};
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setInitiatorCookie(initiatorCookie);
        assertArrayEquals(initiatorCookie, instance.getInitiatorCookie());
    }

    /**
     * Test of setInitiatorCookie method, of class ISAKMPMessage.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSetOverlongInitiatorCookie() {
        byte[] initiatorCookie = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setInitiatorCookie(initiatorCookie);
    }

    /**
     * Test of getResponderCookie method, of class ISAKMPMessage.
     */
    @Test
    public void testGetResponderCookie() {
        ISAKMPMessage instance = new ISAKMPMessage();
        byte[] expResult = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] result = instance.getResponderCookie();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of setResponderCookie method, of class ISAKMPMessage.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSetOverlongResponderCookie() {
        byte[] responderCookie = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setResponderCookie(responderCookie);
    }

    /**
     * Test of setMajorVersion method, of class ISAKMPMessage.
     */
    @Test
    public void testSetMajorVersion() {
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setMajorVersion((byte) 0x0);
        assertEquals(0x00, instance.getVersion());
        instance.setMajorVersion((byte) 0x2);
        assertEquals(0x20, instance.getVersion());
    }

    /**
     * Test of setMajorVersion method, of class ISAKMPMessage.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSetWrongMajorVersion() {
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setMajorVersion((byte) 0x10);
    }

    /**
     * Test of setMinorVersion method, of class ISAKMPMessage.
     */
    @Test
    public void testSetMinorVersion() {
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setMinorVersion((byte) 0x0);
        assertEquals(0x10, instance.getVersion());
        instance.setMinorVersion((byte) 0x2);
        assertEquals(0x12, instance.getVersion());
    }

    /**
     * Test of setMajorVersion method, of class ISAKMPMessage.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSetWrongMinorVersion() {
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setMinorVersion((byte) 0x10);
    }

    /**
     * Test of flags, of class ISAKMPMessage.
     */
    @Test
    public void testSetFlags() {
        ISAKMPMessage instance = new ISAKMPMessage();
        assertEquals(0x00, instance.getFlags());
        instance.setEncryptedFlag(true);
        assertEquals(0x01, instance.getFlags());
        instance.setCommitFlag(true);
        assertEquals(0x03, instance.getFlags());
        instance.setAuthenticationOnlyFlag(true);
        assertEquals(0x07, instance.getFlags());
        instance.setCommitFlag(false);
        assertEquals(0x05, instance.getFlags());
    }

    /**
     * Test of getBytes method, of class ISAKMPMessage. This message was
     * extracted from a Wireshark dump. This implicitely also tests getLength().
     */
    @Test
    public void testGetBytesWithoutPayload() {
        ISAKMPMessage instance = new ISAKMPMessage();
        instance.setInitiatorCookie(new byte[]{0x63, 0x31, 0x32, 0x41, 0x4a, 0x48, 0x4e, 0x78});
        instance.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        byte[] expResult = new byte[]{
            0x63, 0x31, 0x32, 0x41, 0x4a, 0x48, 0x4e, 0x78,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x1c};
        assertArrayEquals(expResult, instance.getBytes());
    }

}
