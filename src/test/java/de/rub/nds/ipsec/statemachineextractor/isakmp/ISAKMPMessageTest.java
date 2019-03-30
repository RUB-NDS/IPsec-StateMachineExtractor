/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.util.Arrays;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ISAKMPMessageTest {

    public ISAKMPMessageTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getInitiatorCookie method, of class ISAKMPMessage.
     */
    @Test
    public void testGetInitiatorCookie() {
        ISAKMPMessage instance = new ISAKMPMessageImpl();
        byte[] result = instance.getInitiatorCookie();
        assertEquals(8, result.length);
    }

    /**
     * Test of setInitiatorCookie method, of class ISAKMPMessage.
     */
    @Test
    public void testSetInitiatorCookie() {
        byte[] initiatorCookie = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D};
        ISAKMPMessage instance = new ISAKMPMessageImpl();
        instance.setInitiatorCookie(initiatorCookie);
        assertArrayEquals(initiatorCookie, instance.getInitiatorCookie());
    }

    /**
     * Test of setInitiatorCookie method, of class ISAKMPMessage.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSetOverlongInitiatorCookie() {
        byte[] initiatorCookie = new byte[]{0x0A, 0x0B, 0x0C, 0x0D, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
        ISAKMPMessage instance = new ISAKMPMessageImpl();
        instance.setInitiatorCookie(initiatorCookie);
    }

    /**
     * Test of getResponderCookie method, of class ISAKMPMessage.
     */
    @Test
    public void testGetResponderCookie() {
        ISAKMPMessage instance = new ISAKMPMessageImpl();
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
        ISAKMPMessage instance = new ISAKMPMessageImpl();
        instance.setResponderCookie(responderCookie);
    }

    /**
     * Test of setMajorVersion method, of class ISAKMPMessage.
     */
    @Test
    public void testSetMajorVersion() {
        ISAKMPMessage instance = new ISAKMPMessageImpl();
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
        ISAKMPMessage instance = new ISAKMPMessageImpl();
        instance.setMajorVersion((byte) 0x10);
    }

    /**
     * Test of setMinorVersion method, of class ISAKMPMessage.
     */
    @Test
    public void testSetMinorVersion() {
        ISAKMPMessage instance = new ISAKMPMessageImpl();
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
        ISAKMPMessage instance = new ISAKMPMessageImpl();
        instance.setMinorVersion((byte) 0x10);
    }

    /**
     * Test of flags, of class ISAKMPMessage.
     */
    @Test
    public void testSetFlags() {
        ISAKMPMessage instance = new ISAKMPMessageImpl();
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
    public void testGetBytes() {
        ISAKMPMessage instance = new ISAKMPMessageImpl();
        instance.setInitiatorCookie(new byte[]{0x63, 0x31, 0x32, 0x41, 0x4a, 0x48, 0x4e, 0x78});
        instance.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        byte[] expResult = new byte[]{
            0x63, 0x31, 0x32, 0x41, 0x4a, 0x48, 0x4e, 0x78,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x1c};
        System.out.println(Arrays.toString(instance.getBytes()));
        assertArrayEquals(expResult, instance.getBytes());
    }

    public class ISAKMPMessageImpl extends ISAKMPMessage {
    }

}
