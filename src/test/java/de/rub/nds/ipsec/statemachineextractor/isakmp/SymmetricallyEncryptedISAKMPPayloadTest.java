/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.CipherAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SymmetricallyEncryptedISAKMPPayloadTest {

    static final SecretKeySpec TEST_KEY_DES = new SecretKeySpec(DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFF"), "DES");
    private static final SecretKeySpec TEST_KEY_AES = new SecretKeySpec(DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), "AES");
    static final byte[] TEST_IV = DatatypeHelper.hexDumpToByteArray("1A1A1A1A1A1B1C1D");
    static final byte[] TEST_HASH = DatatypeHelper.hexDumpToByteArray("AABBCCDDAABBCCDD");
    static final byte[] TEST_HASH_ENC = DatatypeHelper.hexDumpToByteArray("0AE7097DDF4EABE455028CFAF36400CD");
    private static final byte[] TEST_HASH_PAYLOAD_ENC = DatatypeHelper.hexDumpToByteArray("000000140AE7097DDF4EABE455028CFAF36400CD");

    @Test
    public void testAddRFC2409PaddingB64() throws Exception {
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.DES_CBC);
        SymmetricallyEncryptedISAKMPPayload instance = new SymmetricallyEncryptedISAKMPPayload(new HashPayload(), cs, TEST_KEY_DES);
        byte[] inwspace, actual, expected;

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFF");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFF00");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFF");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFF0001");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFF");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFF000002");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FF");
        expected = DatatypeHelper.hexDumpToByteArray("FF00000000000006");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFF");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFF0000000000000007");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);
    }

    /**
     * Test of addRFC2409Padding method, of class
     * SymmetricallyEncryptedISAKMPPayload.
     */
    @Test
    public void testAddRFC2409PaddingB128() throws Exception {
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.AES_CBC);
        SymmetricallyEncryptedISAKMPPayload instance = new SymmetricallyEncryptedISAKMPPayload(new HashPayload(), cs, TEST_KEY_AES);
        byte[] inwspace, actual, expected;

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFF0001");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFF");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFF000002");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FF");
        expected = DatatypeHelper.hexDumpToByteArray("FF00000000000000000000000000000E");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000F");
        actual = instance.addRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);
    }

    /**
     * Test of removeRFC2409Padding method, of class
     * SymmetricallyEncryptedISAKMPPayload.
     */
    @Test
    public void testRemoveRFC2409PaddingB64() throws Exception {
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.DES_CBC);
        SymmetricallyEncryptedISAKMPPayload instance = new SymmetricallyEncryptedISAKMPPayload(new HashPayload(), cs, TEST_KEY_DES);
        byte[] inwspace, actual, expected;

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFF00");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFF0001");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFF000002");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FF00000000000006");
        expected = DatatypeHelper.hexDumpToByteArray("FF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFF0000000000000007");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);
    }

    /**
     * Test of removeRFC2409Padding method, of class
     * SymmetricallyEncryptedISAKMPPayload.
     */
    @Test
    public void testRemoveRFC2409PaddingB128() throws Exception {
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.AES_CBC);
        SymmetricallyEncryptedISAKMPPayload instance = new SymmetricallyEncryptedISAKMPPayload(new HashPayload(), cs, TEST_KEY_AES);
        byte[] inwspace, actual, expected;

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFF0001");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFF000002");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FF00000000000000000000000000000E");
        expected = DatatypeHelper.hexDumpToByteArray("FF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000F");
        expected = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);

        inwspace = DatatypeHelper.hexDumpToByteArray("0000000000000000000000000000000F");
        expected = new byte[0];
        actual = instance.removeRFC2409Padding(inwspace);
        assertArrayEquals(expected, actual);
    }

    /**
     * Test of removeRFC2409Padding method, of class
     * SymmetricallyEncryptedISAKMPPayload.
     */
    @Test(expected = IllegalBlockSizeException.class)
    public void testRemoveRFC2409PaddingWrongPadding1() throws Exception {
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.DES_CBC);
        SymmetricallyEncryptedISAKMPPayload instance = new SymmetricallyEncryptedISAKMPPayload(new HashPayload(), cs, TEST_KEY_DES);

        byte[] inwspace = DatatypeHelper.hexDumpToByteArray("AABBCCDDAABBCC");
        instance.removeRFC2409Padding(inwspace);
        fail();
    }

    /**
     * Test of removeRFC2409Padding method, of class
     * SymmetricallyEncryptedISAKMPPayload.
     */
    @Test(expected = BadPaddingException.class)
    public void testRemoveRFC2409PaddingWrongPadding2() throws Exception {
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.DES_CBC);
        SymmetricallyEncryptedISAKMPPayload instance = new SymmetricallyEncryptedISAKMPPayload(new HashPayload(), cs, TEST_KEY_DES);

        byte[] inwspace = DatatypeHelper.hexDumpToByteArray("AABBCCDDAABBCCDD");
        instance.removeRFC2409Padding(inwspace);
        fail();
    }

    /**
     * Test of removeRFC2409Padding method, of class
     * SymmetricallyEncryptedISAKMPPayload.
     */
    @Test(expected = BadPaddingException.class)
    public void testRemoveRFC2409PaddingWrongPadding3() throws Exception {
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.DES_CBC);
        SymmetricallyEncryptedISAKMPPayload instance = new SymmetricallyEncryptedISAKMPPayload(new HashPayload(), cs, TEST_KEY_DES);

        byte[] inwspace = DatatypeHelper.hexDumpToByteArray("AABBCCDDAA010102");
        instance.removeRFC2409Padding(inwspace);
        fail();
    }

    /**
     * Test of encrypt method, of class SymmetricallyEncryptedISAKMPPayload.
     */
    @Test
    public void testEncrypt() throws Exception {
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(TEST_HASH);
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.DES_CBC);
        SymmetricallyEncryptedISAKMPPayload instance = new SymmetricallyEncryptedISAKMPPayload(hashPayload, cs, TEST_KEY_DES, TEST_IV);
        assertArrayEquals(TEST_HASH_ENC, instance.getCiphertext());
    }

    /**
     * Test of fromStream method, of class SymmetricallyEncryptedISAKMPPayload.
     */
    @Test
    public void testFromStream() throws Exception {
        IKEv1Ciphersuite cs = new IKEv1Ciphersuite();
        cs.setCipher(CipherAttributeEnum.DES_CBC);
        ByteArrayInputStream bais = new ByteArrayInputStream(TEST_HASH_PAYLOAD_ENC);
        SymmetricallyEncryptedISAKMPPayload instance = SymmetricallyEncryptedISAKMPPayload.fromStream(HashPayload.class, bais, cs, TEST_KEY_DES, TEST_IV);
        assertArrayEquals(TEST_HASH, ((HashPayload) instance.getUnderlyingPayload()).getHashData());
        assertEquals(0, bais.available());
    }

}
