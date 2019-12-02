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

    private static final SecretKey CASE56_KEY = new SecretKeySpec(DatatypeHelper.hexDumpToByteArray("90d382b410eeba7ad938c46cec1a82bf"), "AES");
    private static final SecretKey CASE78_KEY = new SecretKeySpec(DatatypeHelper.hexDumpToByteArray("0123456789abcdef0123456789abcdef"), "AES");
    private static final byte[] CASE5_MSG = DatatypeHelper.hexDumpToByteArray("0000432100000001e96e8c08ab465763fd098d45dd3ff893f663c25d325c18c6a9453e194e120849a4870b66cc6b9965330013b4898dc856a4699e523a55db080b59ec3a8e4b7e52775b07d1db34ed9c538ab50c551b874aa269add047ad2d5913ac19b7cfbad4a6");
    private static final byte[] CASE5_PAYLOAD = DatatypeHelper.hexDumpToByteArray("08000ebda70a00008e9c083db95b070008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");
    private static final byte[] CASE6_MSG = DatatypeHelper.hexDumpToByteArray("000043210000000869d08df7d203329db093fc4924e5bd80f51995881ec4e0c4488987ce742e8109689bb379d2d750c0d915dca346a89f75");
    private static final byte[] CASE6_PAYLOAD = DatatypeHelper.hexDumpToByteArray("0800b5e8a80a0500a69c083d0b660e00777777777777777777777777");
    private static final byte[] CASE7_MSG = DatatypeHelper.hexDumpToByteArray("0000876500000002f4e765244f6407adf13dc1380f673f37773b5241a4c449225e4f3ce5ed611b0c237ca96cf74a93013c1b0ea1a0cf70f8e4ecaec78ac53aad7a0f022b859243c647752e94a859352b8a4d4d2decd136e5c177f132ad3fbfb2201ac9904c74ee0a109e0ca1e4dfe9d5a100b842f1c22f0d");
    private static final byte[] CASE7_PAYLOAD = DatatypeHelper.hexDumpToByteArray("45000054090400004001f988c0a87b03c0a87bc808009f76a90a0100b49c083d02a2040008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");
    private static final byte[] CASE8_MSG = DatatypeHelper.hexDumpToByteArray("000087650000000585d47224b5f3dd5d2101d4ea8dffab2215b92683819596a8047232cc00f7048fe45318e11f8a0f62ede3c3fc61203bb50f980a08c9843fd3a1b06d5c07ff9639b7eb7dfb3512e5de435e7207ed971ef3d2726d9b5ef6affc6d17a0decbb13892");
    private static final byte[] CASE8_PAYLOAD = DatatypeHelper.hexDumpToByteArray("45000044090c00004001f990c0a87b03c0a87bc80800d63caa0a0200c69c083da3de0300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    @Test
    public void testRFC3602TestVectorCase5() throws Exception {
        final byte[] TEST_IV = DatatypeHelper.hexDumpToByteArray("e96e8c08ab465763fd098d45dd3ff893");
        ESPMessage instance = new ESPMessage(CASE56_KEY, "AES", "CBC", TEST_IV);
        instance.setSpi(new byte[]{0x00, 0x00, 0x43, 0x21});
        instance.setSequenceNumber(1);
        instance.setPayloadData(CASE5_PAYLOAD);
        instance.setNextHeader((byte) 0x01);
        byte[] result = instance.getBytes();
        byte[] expResult = CASE5_MSG;
        assertArrayEquals(expResult, result);
    }

    @Test
    public void testRFC3602TestVectorCase5Reverse() throws Exception {
        ESPMessage instance = ESPMessage.fromBytes(CASE5_MSG, CASE56_KEY, "AES", "CBC");
        assertArrayEquals(new byte[]{0x00, 0x00, 0x43, 0x21}, instance.getSpi());
        assertEquals(1, instance.getSequenceNumber());
        assertArrayEquals(CASE5_PAYLOAD, instance.getPayloadData());
        assertEquals(14, instance.getPadLength());
        assertEquals(1, instance.getNextHeader());
    }

    @Test
    public void testRFC3602TestVectorCase6() throws Exception {
        final byte[] TEST_IV = DatatypeHelper.hexDumpToByteArray("69d08df7d203329db093fc4924e5bd80");
        ESPMessage instance = new ESPMessage(CASE56_KEY, "AES", "CBC", TEST_IV);
        instance.setSpi(new byte[]{0x00, 0x00, 0x43, 0x21});
        instance.setSequenceNumber(8);
        instance.setPayloadData(CASE6_PAYLOAD);
        instance.setNextHeader((byte) 0x01);
        byte[] result = instance.getBytes();
        byte[] expResult = CASE6_MSG;
        assertArrayEquals(expResult, result);
    }

    @Test
    public void testRFC3602TestVectorCase6Reverse() throws Exception {
        ESPMessage instance = ESPMessage.fromBytes(CASE6_MSG, CASE56_KEY, "AES", "CBC");
        assertArrayEquals(new byte[]{0x00, 0x00, 0x43, 0x21}, instance.getSpi());
        assertEquals(8, instance.getSequenceNumber());
        assertArrayEquals(CASE6_PAYLOAD, instance.getPayloadData());
        assertEquals(1, instance.getNextHeader());
    }

    @Test
    public void testRFC3602TestVectorCase7() throws Exception {
        final byte[] TEST_IV = DatatypeHelper.hexDumpToByteArray("f4e765244f6407adf13dc1380f673f37");
        ESPMessage instance = new ESPMessage(CASE78_KEY, "AES", "CBC", TEST_IV);
        instance.setSpi(new byte[]{0x00, 0x00, (byte) 0x87, (byte) 0x65});
        instance.setSequenceNumber(2);
        instance.setPayloadData(CASE7_PAYLOAD);
        instance.setNextHeader((byte) 0x04);
        byte[] result = instance.getBytes();
        byte[] expResult = CASE7_MSG;
        assertArrayEquals(expResult, result);
    }

    @Test
    public void testRFC3602TestVectorCase7Reverse() throws Exception {
        ESPMessage instance = ESPMessage.fromBytes(CASE7_MSG, CASE78_KEY, "AES", "CBC");
        assertArrayEquals(new byte[]{0x00, 0x00, (byte) 0x87, (byte) 0x65}, instance.getSpi());
        assertEquals(2, instance.getSequenceNumber());
        assertArrayEquals(CASE7_PAYLOAD, instance.getPayloadData());
        assertEquals(4, instance.getNextHeader());
    }
    
    @Test
    public void testRFC3602TestVectorCase8() throws Exception {
        final byte[] TEST_IV = DatatypeHelper.hexDumpToByteArray("85d47224b5f3dd5d2101d4ea8dffab22");
        ESPMessage instance = new ESPMessage(CASE78_KEY, "AES", "CBC", TEST_IV);
        instance.setSpi(new byte[]{0x00, 0x00, (byte) 0x87, (byte) 0x65});
        instance.setSequenceNumber(5);
        instance.setPayloadData(CASE8_PAYLOAD);
        instance.setNextHeader((byte) 0x04);
        byte[] result = instance.getBytes();
        byte[] expResult = CASE8_MSG;
        assertArrayEquals(expResult, result);
    }
    
    @Test
    public void testRFC3602TestVectorCase8Reverse() throws Exception {
        ESPMessage instance = ESPMessage.fromBytes(CASE8_MSG, CASE78_KEY, "AES", "CBC");
        assertArrayEquals(new byte[]{0x00, 0x00, (byte) 0x87, (byte) 0x65}, instance.getSpi());
        assertEquals(5, instance.getSequenceNumber());
        assertArrayEquals(CASE8_PAYLOAD, instance.getPayloadData());
        assertEquals(4, instance.getNextHeader());
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
