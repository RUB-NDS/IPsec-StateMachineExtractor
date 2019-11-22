package de.rub.nds.ipsec.statemachineextractor.ipsec;

import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ESPMessageTest {

    static {
        CryptoHelper.prepare();
    }

    @Test
    public void testRFC3602TestVectorCase5() throws Exception {
        final SecretKey TEST_KEY_AES = new SecretKeySpec(DatatypeHelper.hexDumpToByteArray("90d382b410eeba7ad938c46cec1a82bf"), "AES");
        final byte[] TEST_IV = DatatypeHelper.hexDumpToByteArray("e96e8c08ab465763fd098d45dd3ff893");
        ESPMessage instance = new ESPMessage(TEST_KEY_AES, "AES", "CBC", TEST_IV);
        instance.setSpi(new byte[]{0x00, 0x00, 0x43, 0x21});
        instance.setSequenceNumber(1);
        instance.setPayloadData(DatatypeHelper.hexDumpToByteArray("08000ebda70a00008e9c083db95b070008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"));
        instance.setNextHeader((byte) 0x01);
        byte[] result = instance.getBytes();
        byte[] expResult = DatatypeHelper.hexDumpToByteArray("0000432100000001e96e8c08ab465763fd098d45dd3ff893f663c25d325c18c6a9453e194e120849a4870b66cc6b9965330013b4898dc856a4699e523a55db080b59ec3a8e4b7e52775b07d1db34ed9c538ab50c551b874aa269add047ad2d5913ac19b7cfbad4a6");
        assertArrayEquals(expResult, result);
    }

    @Test
    public void testRFC3602TestVectorCase5Reverse() throws Exception {
        final SecretKey TEST_KEY_AES = new SecretKeySpec(DatatypeHelper.hexDumpToByteArray("90d382b410eeba7ad938c46cec1a82bf"), "AES");
        ESPMessage instance = ESPMessage.fromBytes(DatatypeHelper.hexDumpToByteArray("0000432100000001e96e8c08ab465763fd098d45dd3ff893f663c25d325c18c6a9453e194e120849a4870b66cc6b9965330013b4898dc856a4699e523a55db080b59ec3a8e4b7e52775b07d1db34ed9c538ab50c551b874aa269add047ad2d5913ac19b7cfbad4a6"), TEST_KEY_AES, "AES", "CBC");
        assertArrayEquals(new byte[]{0x00, 0x00, 0x43, 0x21}, instance.getSpi());
        assertEquals(1, instance.getSequenceNumber());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("08000ebda70a00008e9c083db95b070008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"), instance.getPayloadData());
        assertEquals(14, instance.getPadLength());
        assertEquals(1, instance.getNextHeader());
    }

    @Test
    public void testRFC3602TestVectorCase6() throws Exception {
        final SecretKey TEST_KEY_AES = new SecretKeySpec(DatatypeHelper.hexDumpToByteArray("90d382b410eeba7ad938c46cec1a82bf"), "AES");
        final byte[] TEST_IV = DatatypeHelper.hexDumpToByteArray("69d08df7d203329db093fc4924e5bd80");
        ESPMessage instance = new ESPMessage(TEST_KEY_AES, "AES", "CBC", TEST_IV);
        instance.setSpi(new byte[]{0x00, 0x00, 0x43, 0x21});
        instance.setSequenceNumber(8);
        instance.setPayloadData(DatatypeHelper.hexDumpToByteArray("0800b5e8a80a0500a69c083d0b660e00777777777777777777777777"));
        instance.setNextHeader((byte) 0x01);
        byte[] result = instance.getBytes();
        byte[] expResult = DatatypeHelper.hexDumpToByteArray("000043210000000869d08df7d203329db093fc4924e5bd80f51995881ec4e0c4488987ce742e8109689bb379d2d750c0d915dca346a89f75");
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of addRFC2406Padding method, of class ESPMessage.
     */
    @Test
    public void testAddRFC2406Padding() throws Exception {
        byte[] in, expResult, result;
        ESPMessage instance = new ESPMessage(new SecretKeySpec(DatatypeHelper.hexDumpToByteArray("000102030405060708090A0B0C0D0E0F"), "AES"), "AES", "CBC");

        in = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFF");
        expResult = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFF01020304050607080800");
        result = instance.addRFC2406Padding(in);
        assertArrayEquals(expResult, result);

        in = DatatypeHelper.hexDumpToByteArray("FF");
        expResult = DatatypeHelper.hexDumpToByteArray("FF0102030405060708090A0B0C0D0D00");
        result = instance.addRFC2406Padding(in);
        assertArrayEquals(expResult, result);

        in = DatatypeHelper.hexDumpToByteArray("");
        expResult = DatatypeHelper.hexDumpToByteArray("0102030405060708090A0B0C0D0E0E00");
        result = instance.addRFC2406Padding(in);
        assertArrayEquals(expResult, result);

        in = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"); // 15 bytes 0x255
        expResult = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0102030405060708090A0B0C0D0E0F0F00");
        result = instance.addRFC2406Padding(in);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of removeRFC2406Padding method, of class ESPMessage.
     */
    @Test
    public void testRemoveRFC2406Padding() throws Exception {
        byte[] in, expResult, result;
        ESPMessage instance = new ESPMessage(new SecretKeySpec(DatatypeHelper.hexDumpToByteArray("000102030405060708090A0B0C0D0E0F"), "AES"), "AES", "CBC");

        in = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFF01020304050607080800");
        expResult = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFF");
        result = instance.removeRFC2406Padding(in);
        assertArrayEquals(expResult, result);

        in = DatatypeHelper.hexDumpToByteArray("FF0102030405060708090A0B0C0D0D00");
        expResult = DatatypeHelper.hexDumpToByteArray("FF");
        result = instance.removeRFC2406Padding(in);
        assertArrayEquals(expResult, result);

        in = DatatypeHelper.hexDumpToByteArray("0102030405060708090A0B0C0D0E0E00");
        expResult = DatatypeHelper.hexDumpToByteArray("");
        result = instance.removeRFC2406Padding(in);
        assertArrayEquals(expResult, result);

        in = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0102030405060708090A0B0C0D0E0F0F00");
        expResult = DatatypeHelper.hexDumpToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        result = instance.removeRFC2406Padding(in);
        assertArrayEquals(expResult, result);
    }

}
