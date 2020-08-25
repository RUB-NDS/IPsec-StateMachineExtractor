package de.rub.nds.ipsec.statemachineextractor.ike.v2;

import de.rub.nds.ipsec.statemachineextractor.ike.v2.payloads.IdentificationPayloadInitiator;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.net.InetAddress;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2HandshakeSessionSecretsTest {
    
    static {
        CryptoHelper.prepare();
    }

    /**
     * Test of computeSecretKeys method, of class IKEv2HandshakeSessionSecrets.
     */
    @Test
    public void testComputeSecretKeys() throws Exception {
        IKEv2Handshake handshake = new IKEv2Handshake(0, InetAddress.getLocalHost(), 500);
        IKEv2HandshakeSessionSecrets instance = handshake.secrets;
        instance.generateDefaults();
        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        instance.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("63ff9cfe89d87d4d"));
        instance.setResponderCookie(DatatypeHelper.hexDumpToByteArray("f5d983d823f8368e"));
        instance.getHandshakeSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("e762301bccfa1d6eddb38763b18a8477919490474f2c5cab79b98e3efd9a9db8"));
        instance.getHandshakeSA().setResponderNonce(DatatypeHelper.hexDumpToByteArray("a917b901dee4be6f6d16751590593efd4b0925c7f7fd1f92212124e3ddbff363"));
        instance.getHandshakeSA().setDHSecret(DatatypeHelper.hexDumpToByteArray("86F307E06C76197CEBAC720D0BFE77084E10276312C00578CBC12D01FDA2393FA7E482165E4277CB1A7CA924ED009823C9A34CE1A3435EE3ABFC8F2DC0C5089C089371F6B933C5E5478AEF75EA98C87750B81D273C0F525CB8AA2BC65C4DD267F529D563151A274F29B22BC0C59730A9CDA0C255A2ED12616E42EFA1ED2B093E"));
        
        instance.computeSecretKeys();
        
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("74337BF3C908320F5DF877C57D4E82B04D33778F"), instance.getSKeyseed());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("5B2C8054E66DFC6AADE3791225AD1922C213E0BE"), instance.getSKd());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("7BFC0D2E7ADB01053B678868706AA73AFEE8287D"), instance.getSKai());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("1441BD4D23DFE2D5FD72161F13112F807146E638"), instance.getSKar());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("331DA949C7B71BF4E7DA21A46479C6C2"), instance.getSKei());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("5250A02CD7150482DF614FCFDBEC850B"), instance.getSKer());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("15FF3616C546076E177A9BCCEBBE432B8A472B11"), instance.getSKpi());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("2A5547F1AE6BCDCBF8A46A202C37D763148274F6"), instance.getSKpr());
    }
    
    /**
     * Test of computeAUTH method, of class IKEv2HandshakeSessionSecrets.
     */
    @Test
    public void testComputeAUTH() throws Exception {
        IKEv2Handshake handshake = new IKEv2Handshake(0, InetAddress.getLocalHost(), 500);
        IKEv2HandshakeSessionSecrets instance = handshake.secrets;
        instance.generateDefaults();
        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        instance.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("2b52e39c2e82e183"));
        instance.setResponderCookie(DatatypeHelper.hexDumpToByteArray("c879baa6a447bcdd"));
        instance.getHandshakeSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("33a0e2cd09e93052e4ce64aa9b6f578b6a34361c73a1b2828543982cfb678a7b"));
        instance.getHandshakeSA().setResponderNonce(DatatypeHelper.hexDumpToByteArray("7ca2b80b46c1de45649076a0d594a8c39e91492b1457a06f514685d58b25d62b"));
        instance.getHandshakeSA().setDHSecret(DatatypeHelper.hexDumpToByteArray("1A16CE7E3ED40C345B78A00130BD05C4B833C0581635C205933117287AA7D919E3E76FA696D5D1FBF7535EFADF5A9AB2801CCC02AE227D46944ADAF9E6CFB313C458A2AF6CBC797BF2F3FE40C4DBEB539AF7A45D9EF14470194BCD28AFE155A3B5650FA2EC2C42453C3731838D38ED6331ED2A1E6C8573BE0D7F96A5F4125777"));
        
        instance.computeSecretKeys();
        
        instance.setMessage(DatatypeHelper.hexDumpToByteArray("2b52e39c2e82e18300000000000000002120220800000000000000f8220000300000002c010100040300000c0100000c800e00800300000802000002030000080300000200000008040000022800008800020000542f00a1ff961603b24e95ad10fa079542b2d0d1d0f6b569fc2b8267060c5bf09a1ecebbdb6f4b92b2a7e2432097f786a0441980b489830667040c3ab8611ea9f5160ff06661acb4144f98a29a4f371d996e7e08c9f7f0697febccac294755f5c201c481d9bc2b80e0b03cb3bd2202ec4476266437f631a6581bd1242b46ec200000002433a0e2cd09e93052e4ce64aa9b6f578b6a34361c73a1b2828543982cfb678a7b"));
        IdentificationPayloadInitiator IDi = new IdentificationPayloadInitiator();
        IDi.setIdType(IDTypeEnum.IPV4_ADDR);
        IDi.setIdentificationData(new byte[]{0x0A, 0x00, 0x03, 0x01});
        IDi.setIDi();
        instance.setIDi(IDi.getIDi());
        
        instance.computeOctets();
        
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("2B52E39C2E82E18300000000000000002120220800000000000000F8220000300000002C010100040300000C0100000C800E00800300000802000002030000080300000200000008040000022800008800020000542F00A1FF961603B24E95AD10FA079542B2D0D1D0F6B569FC2B8267060C5BF09A1ECEBBDB6F4B92B2A7E2432097F786A0441980B489830667040C3AB8611EA9F5160FF06661ACB4144F98A29A4F371D996E7E08C9F7F0697FEBCCAC294755F5C201C481D9BC2B80E0B03CB3BD2202EC4476266437F631A6581BD1242B46EC200000002433A0E2CD09E93052E4CE64AA9B6F578B6A34361C73A1B2828543982CFB678A7B7CA2B80B46C1DE45649076A0D594A8C39E91492B1457A06F514685D58B25D62B2E75DCC312CEB4F1B314D6F96FCA15C6A55C6B5C"), instance.getOctets());        
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("0E803C0E948745852A806404630EA4D10DD64568"), instance.computeAUTH());
    }
}
