/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1HandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeSessionSecretsTest {

    static {
        CryptoHelper.prepare();
    }

    /**
     * Test of computeSecretKeys method, of class IKEv1HandshakeSessionSecrets.
     */
    @Test
    public void testComputeSecretKeys() throws Exception {
        IKEHandshake handshake = new IKEHandshake(0, InetAddress.getLocalHost(), 500);
        handshake.adjustCiphersuite(SecurityAssociationPayloadFactory.V1_P1_PSK_AES128_SHA1_G2);
        IKEv1HandshakeSessionSecrets instance = handshake.secrets_v1;
        instance.generateDefaults();
        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        instance.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("7116900aa5c2880d"));
        instance.setResponderCookie(DatatypeHelper.hexDumpToByteArray("047ad6f8b3d0abb7"));
        instance.getHandshakeSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("4654fdd74594982a"));
        instance.getHandshakeSA().setResponderNonce(DatatypeHelper.hexDumpToByteArray("3673e64987b4956dbb8b933399251a5abf88f557a723b802b345f838667e9a4e"));
        instance.getHandshakeSA().setKeyExchangeData(DatatypeHelper.hexDumpToByteArray("75fb75db0749d4b15d9bb067b63399f790246dd7919d0c0a88fc34dd76eb9ad204e162b261914c0966a2d32d05178d4c0f0ec3817692fca675678f2fd2a6869188b943e33ad44cc859a5af98d6d5332c538cff4174ee737c8624de910cc40bd953f7940d1b2d8a681cee03c85199fbe773bfa100ffea5fcb82eed25a399b0b3e"));
        instance.getHandshakeSA().setPeerKeyExchangeData(DatatypeHelper.hexDumpToByteArray("2096a31ff922e5224d9d19f06a41e2d9aebe1180d4e5cbc3d6ea166e2b8810d5ddd048375025ae9bf895ad40c508cd8b9398bded0d00ae7e77c1a1eb31930495106892630152a926a45037606cda4651340082fc10558786b4d8c4e6d72222d580d9a30d9c3b7fe9c348a6eadc5e79a24fe4b4364297b5ff71914ef8a6980e73"));
        instance.getHandshakeSA().setSAOfferBody(DatatypeHelper.hexDumpToByteArray("00000001000000010000002c01010001000000240101000080010007800e0080800200028004000280030001800b0001800c7080"));
        instance.setPeerIdentificationPayloadBody(DatatypeHelper.hexDumpToByteArray("010000000a00030a"));
        instance.getHandshakeSA().setDHSecret(DatatypeHelper.hexDumpToByteArray("19B67B23EB5F792EC9D7E11D16501CA20F2A2D0B230D525CD824DFB16867B515DC2CE9560B20B2149BFB360C1662C26A5AD7FE1FAA86E66213238C80B2ED46CCB821BF5043093027EB6E32C71685A093306DF20C24190C7F93947FA21E56D10E4C5B7063B2B4DC1747F1DF0BD46975D1825EEDE335E3ACBAD71A063CECF866C7"));

        instance.computeSecretKeys();

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("49856BC53F30DB8CE55F5BEFAE9E42431279550C"), instance.getSKEYID());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("E5D7368180A8766F09C90CC9AC15182D3CD492EE"), instance.getSKEYID_d());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("92DE109FE83047C95812B600820F1476CD24AA49"), instance.getSKEYID_a());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("DE5D24679AD21491E63E2D7173017769CD7B9BC5"), instance.getSKEYID_e());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("DE5D24679AD21491E63E2D7173017769"), instance.getKa());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("139568606DF1337CBCBC8FA7D201C8A8"), instance.getIV(new byte[]{0x00, 0x00, 0x00, 0x00}));
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("BA8C49CFD796BDC78E63FF6B5A858FC289DAD933"), instance.getHASH_R());
    }

    /**
     * Test of computeSecretKeys method, of class IKEv1HandshakeSessionSecrets.
     */
    @Test
    public void testComputeSecretKeysInformationalExchange() throws Exception {
        IKEHandshake handshake = new IKEHandshake(0, InetAddress.getLocalHost(), 500);
        handshake.adjustCiphersuite(SecurityAssociationPayloadFactory.V1_P1_PSK_AES128_SHA1_G2);
        IKEv1HandshakeSessionSecrets instance = handshake.secrets_v1;
        instance.generateDefaults();
        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        instance.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("dc3f1d7452b2c376"));
        instance.setResponderCookie(DatatypeHelper.hexDumpToByteArray("5f17969262b7829b"));
        instance.getHandshakeSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("18eeeee5b29ef938"));
        instance.getHandshakeSA().setResponderNonce(DatatypeHelper.hexDumpToByteArray("cf6306dcc088a94c1983462f97a3128ecdefbe4a1925cffddedd526215648099"));
        instance.getHandshakeSA().setKeyExchangeData(DatatypeHelper.hexDumpToByteArray("a8b04c567a6bb3ab17da6a07f3f1667e6c70fb992ffe0a01dccc0877214c1936cc13a66aa97e4cd9ebfd61f6a7119859bba763255b54364d37a59f969d230f877cce6d77ca843e5f0cb24e354d51a429aabf75238f5a17ef5801f3b02d9f35dcd3562c35e6aeff67e9c71961f9313b6306c2c1adb428d6e70e713f894d9b7eda"));
        instance.getHandshakeSA().setPeerKeyExchangeData(DatatypeHelper.hexDumpToByteArray("7947cdf90ed5f07ca325c9c9e6de95a82e5728b2e1daf44866100723ad2bed0f09e8383cf89c7645c805c2942d4aebfa1b6c351a9666faa1f4988c3a557cb411a3b73fd3e094144e646ef5eb85118a61f06c6359e0f19b43a99720b49ae322155d462004be5e09140cfc843e0622c6735bc90ab730577fc311b23b25a8d283fa"));
        instance.getHandshakeSA().setSAOfferBody(DatatypeHelper.hexDumpToByteArray("00000001000000010000002c01010001000000240101000080010007800e0080800200028004000280030001800b0001800c7080"));
        instance.setPeerIdentificationPayloadBody(DatatypeHelper.hexDumpToByteArray("010000000a00030a"));
        instance.getHandshakeSA().setDHSecret(DatatypeHelper.hexDumpToByteArray("9FC4267E99D40EE7AA19492615990548621EBED0AE925A0810C2F4BF30A100F6B13201BAC4595281E5F2FB6FAF56F9CDA292991B40B41A48CFBA7713140DE1784DBD525C0CB88A4D3B4B46D7CABD539CDD1E79EDE000420CFFE9ED8BCA0B2FE09208D9D3145F55F68CE0E3C6C479616B64F3EB451CD4CE268310BCDC766BA8A2"));

        instance.computeSecretKeys();

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("505E91CA4127FE30D9CAD15F6176E8C504D2D612"), instance.getSKEYID());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("571D06B00EDA6D375310377F3B3E0994A936E0F2"), instance.getSKEYID_d());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("1DE7B88B63DEEA0BB41374C6F9514F64B894E083"), instance.getSKEYID_a());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("84FAF4DF7DCEC32AC45F13A485E732632160F596"), instance.getSKEYID_e());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("84FAF4DF7DCEC32AC45F13A485E73263"), instance.getKa());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("0E09ED33BAC3584D1D10762A9BD026C1"), instance.getIV(new byte[]{0x00, 0x00, 0x00, 0x00}));
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("DDB2CF1067913E83EA6633B8B174BC8CE559B9D1"), instance.getHASH_R());
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("0BF60ED4C34FEA8A12077A204DFD413F"), instance.getIV(DatatypeHelper.hexDumpToByteArray("d8029d42")));
    }

    /**
     * Test of computeDHSecret method, of class IKEv1HandshakeSessionSecrets.
     */
    @Test
    public void testComputeDHSecret() throws Exception {
        IKEHandshake handshake = new IKEHandshake(0, InetAddress.getLocalHost(), 500);
        handshake.adjustCiphersuite(SecurityAssociationPayloadFactory.V1_P1_PSK_AES128_SHA1_G2);
        IKEv1HandshakeSessionSecrets instance = handshake.secrets_v1;
        PKCS8EncodedKeySpec key1SpecPriv = new PKCS8EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082012102010030819506092A864886F70D01030130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF020102048183028180357449FA7673FCF4FAF97D5BD90F42F7CEF89AF2523D7B49C500377BFE3F8DB3A55DA3AD0ABDD0E363FB69EDEA9F97539F8C9EBABA87C4056A23AA52C6ED5F866EBE68C8F7AA3C4984FE3846BF35D64252DAEC4D52A076220487B8B098FA04F5156E6C68BDCC1D9C156AE80F4DB02ED4B33840FE2C8B5C20D1335CCA08A53EAC"));
        X509EncodedKeySpec key1SpecPub = new X509EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082011D30819306072A8648CE3E020130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0201020381840002818075212BD6A675FB8764A87E119AE2F17CE5AE39F584BD202B7A38F560192F6A2EE60D74917C84D2C2F73275837DEFBC3F1A1290C42E8E8C40786D8262F1A8774DE94556916A138603ED28606C6451C52FA6002A5B82B23407D525584AB12BC94970E42E0A9206ED6985A516739DF996159BCB61B1718F56D05AC96446A598D31B"));
        X509EncodedKeySpec key2SpecPub = new X509EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082011E30819306072A8648CE3E020130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0201020381850002818100B8C8F889D2105EC783B99A62FD792A48628CCAD1D30A9BD19CB0A8D5BE155A7A22F86386E8592A683CE01A8CBE77E48E45702BA82E6E73831E7400ADB77D45E873A3228AA4B76EF02443681FD8CDDA76716A90A4C8006DCBDBD6425A1E2AFC8B8C9837FFD53A69D7747A12A6231ABCDF9B887742E25A86B5C516BFD7CC0F29C8"));
        KeyFactory factory = KeyFactory.getInstance("DH");
        instance.getHandshakeSA().setDhKeyPair(new KeyPair(factory.generatePublic(key1SpecPub), factory.generatePrivate(key1SpecPriv)));
        instance.getHandshakeSA().setPeerKeyExchangeData(CryptoHelper.publicKey2Bytes(factory.generatePublic(key2SpecPub)));
        byte[] secret = instance.getHandshakeSA().computeDHSecret();
        assertEquals(0x00, secret[0]);
        assertEquals(128, secret.length);
    }
}
