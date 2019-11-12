/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.util.LoquaciousClientUdpTransportHandler;
import java.io.IOException;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;

/**
 * Integration tests that mock a responder and replay recorded handshakes.
 * 
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeIT {

    static {
        CryptoHelper.prepare();
    }

    IKEv1Handshake handshake;
    HashMap<String, String> msgPairs = new HashMap<>();

    public IKEv1HandshakeIT() {
        // Aggressive PSK m1 / m2
        msgPairs.put("75cc633d664fd55600000000000000000110040000000000000000f00400003800000001000000010000002c00010001000000240001000080010007800e0080800200028004000280030001800b0001800c70800a000084375427d76a58cf3db4ab3cf2da9dd44dfef6233affc1d34d75c3aec9d93353a29fc3d6ec1fc4c343e49439302cacca1a52d19877a0fa72a1ee023d67015ffc690361606ec24115655228b50d328636f4fce68253d7fbd1eae905cfc6dc93194e147184279556d86ceeeb33a78b612aabdd6590ca4e609cc88906457787f13ff70500000ca3a34f453de42c670000000c010000000a000301",
                "75cc633d664fd5560534fc1813e089e10110040000000000000001400400003800000001000000010000002c00010001000000240101000080010007800e0080800200028004000280030001800b0001800c70800a0000843af9e9bbff0c40ca81e538ccaca7dab906ae2f48f68b3f03e8c81f361b5cf514ef20d46d46b2c513a342dd3ca210dd069ff995c53f363b4e05c5c4534fe566441343333b615d87efa9d55400c44d5b5a02e41872790749df8aff964cf937fc3e349ec31f3b1cab032202389f87784f44ec4878adec2b974bc17156238937133f050000240f03492d4761a688f493d24424e9a7d19f1a64c4cd697dc900862aa1163f06450d00000c010000000a00030a0d00000c09002689dfd6b71208000014afcad71368a1f1c96b8696fc775701000000001891b7a7f96ea7a07c12ae03af0bc32e9f347685bb");
        // Aggressive PSK m3
        msgPairs.put("75cc633d664fd5560534fc1813e089e108100400000000000000003400000018cd7dbe09500affbe969fadb342d021acd65740cf",
                "");
        // Aggressive PSK qm1 / qm2
        msgPairs.put("75cc633d664fd5560534fc1813e089e108102001e582bf040000009c82ec87b994f7ae97adf4eec2e4fd9c14017fd3e954a4d16096b706c1f49e32b24ff178d5f7088b5b40714dfa0dff9c18bceddd1d7ed98c66fa026625c3231b750dc2b26a070ad61767e8bc357ff5e01d405c5eaa6afd52712f3222abba3fb2484d4b571f0e4c8ae5eba1905fd1496e3988469044c6949fda8824c35ba5b4f708",
                "75cc633d664fd5560534fc1813e089e108102001e582bf04000000acfa4cd71d0cd487efb3e7edce0caafcc34f71cd79714cddee45d5c4de9c364ba7763917cc66f4cd7df1fb53b59ec812a5dcff75383f116c67b94a9c5aae8181dfad81a312157c2ccc93344dbfcec169c18f8c9fe66e8c44de5179b2a39c42b5d798a929b03a167caae1f129c6194fabb74143c9ec623720f16de13f20d819cf737be79ac23f2143f5f43bd15109daa2d1");
        // Aggressive PSK qm3
        msgPairs.put("75cc633d664fd5560534fc1813e089e108102001e582bf040000003ccbe867c2849c3ccf5edff6ee8a40c37a35d25439d95103dd2cf4683cfef9f777",
                "");
        // Main PSK m1 / m2
        msgPairs.put("59cedc5dcea558fe00000000000000000110020000000000000000540000003800000001000000010000002c00010001000000240001000080010007800e0080800200028004000280030001800b0001800c7080",
                "59cedc5dcea558fe9e169842364452570110020000000000000000740d00003800000001000000010000002c00010001000000240101000080010007800e0080800200028004000280030001800b0001800c70800d00000c09002689dfd6b71200000014afcad71368a1f1c96b8696fc77570100");
        // Main PSK m3 / m4
        msgPairs.put("59cedc5dcea558fe9e169842364452570410020000000000000000ac0a000084b5fcea14e2593ee937054b98886ca43b00472167db154ff074e158e8b7fcae77ac35cef073698bfe63c99c6dd64ae25a95d55800a845a5db0640d1c3ea5bb8596cb0ffa5d4db0fd01e1875941b14ad4ac492fb5f6381db934664ad8493fe95aab7f1ff8976f329b5ea0f9ede244e906fb419353e878f2fa92ccd533ba33d79ee0000000c32ae9db36e7418a7",
                "59cedc5dcea558fe9e169842364452570410020000000000000000c40a00008424bb23e799283854458c53d6d735ee8c099008c743c89900b312264d3d372e4ff3986d5890d43e5aa7f2c6adb910b302cddcdf773b74921f8ce0376a338a28d7569fb8d4dab85a799cc753bd7d2fd9a65d4e4b016ea9742349c0d8cb6271061e21f5d6af924fddf05fa3a0c83ce7a22074e779c4fee154a728a4c0d6488adbb300000024ce2b9ff5f8519260b6c8f153529bc5a43121e3aa57a3de7d0d63baba86679e57");
        // Main PSK m5 / m6
        msgPairs.put("59cedc5dcea558fe9e1698423644525705100201000000000000004cfabd2d66f56237c7810b25e185b0186559632459fde4ebb654970a62e83cdd47c9201aad89e40e9500d264aeaa968647",
                "59cedc5dcea558fe9e1698423644525705100201000000000000004c56e985c35cd53530527480fcf20a9faa5a3d45465a20f67d48d3e9c55b09b72253d9030fe2f2cf3a3fa1eae37e3fccaa");
        // Main PSK qm1 / qm2
        msgPairs.put("59cedc5dcea558fe9e1698423644525708102001259cf1330000009ce47a7db59b674dbad6139dd85fa848ed708f401a6d3a5f51cb2c7a536f5d66423c8f836ac940ae79ac8de022830196d280c0552a11d68afaceb75855fa45195c35332ffaef8e2bf2d43361b1d6e560927b67651ea2cab184dc27cb20c138e76529b62655bc127f196969fe16cb3229f049b07af51d3bf0c000747cd944c32e12",
                "59cedc5dcea558fe9e1698423644525708102001259cf133000000ac65d4e7d4b983b417b1e567e10fdec60810585f0954817b8192d9501141c458567ac84c42360176d59e7591ac45c4de7dad738657d49bbca9034247f7ab96dac4f43c3d6cccdeeeae62742cb5c79b5a4db4949504f21e96d38a0f75342b421688a1b62b7157ee7a154f2a0a7eef69138db52361827b50a3b62ce53347aee835bcea1a1ef0b1cc04ec7a167ccec3b4cd36");
        // Main PSK qm3
        msgPairs.put("59cedc5dcea558fe9e1698423644525708102001259cf1330000003cf0fa3ae90bfec0179ffa8592af60cf2febe9f682f629e83e497b8644ae726c1c",
                "");
    }

    @Before
    public void setUp() throws Exception {
        handshake = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        handshake.udpTH = new ClientUdpTransportHandlerMock();
    }

    class ClientUdpTransportHandlerMock extends LoquaciousClientUdpTransportHandler {

        byte[] nextResponse;

        public ClientUdpTransportHandlerMock() {
            super(0, "localhost", 0);
        }

        @Override
        public InetAddress getLocalAddress() throws IOException {
            return InetAddress.getByAddress(new byte[]{10, 0, 3, 1});
        }

        @Override
        public void initialize() throws IOException {
        }

        @Override
        public void closeConnection() throws IOException {
        }

        @Override
        public boolean isInitialized() {
            return true;
        }

        @Override
        public void sendData(byte[] data) throws IOException {
            final String dataHex = DatatypeHelper.byteArrayToHexDump(data).toLowerCase();
            if (!msgPairs.containsKey(dataHex)) {
                nextResponse = null;
                throw new IOException("Unexpected Message: " + dataHex);
            }
            nextResponse = DatatypeHelper.hexDumpToByteArray(msgPairs.get(dataHex));
        }

        @Override
        public byte[] fetchData() throws IOException {
            return nextResponse;
        }
    }

    @Test
    public void testAggressiveModePSKHandshake() throws Exception {
        ISAKMPMessage msg, answer;
        SecurityAssociationPayload sa;

        sa = SecurityAssociationPayloadFactory.P1_PSK_AES128_SHA1_G2;
        handshake.adjustCiphersuite(sa);
        IKEv1HandshakeSessionSecrets secrets = handshake.secrets;
        secrets.generateDefaults();

        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        {
            KeySpec spec = new PKCS8EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082012102010030819506092A864886F70D01030130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0201020481830281801445CC10B6FB0AB024B73A55CE8C8CB8689F5473862B337C176B8D976EB04A14F55269413FDE7F88752CD53AA9A4C8CC1ED8282BE43DB4EF6854AE45ED22CFAC2213666DA6D5E7323A934A19455E9D8E53076D15A1C5C36259989717270E2720AE65F34881F0C8417AFC4C7C984882D9864D3BC14B94C26A23B0B76E1F9D7360"));
            KeyFactory kf = KeyFactory.getInstance("DH");
            PrivateKey privkey = kf.generatePrivate(spec);
            spec = new X509EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082011D30819306072A8648CE3E020130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF02010203818400028180375427D76A58CF3DB4AB3CF2DA9DD44DFEF6233AFFC1D34D75C3AEC9D93353A29FC3D6EC1FC4C343E49439302CACCA1A52D19877A0FA72A1EE023D67015FFC690361606EC24115655228B50D328636F4FCE68253D7FBD1EAE905CFC6DC93194E147184279556D86CEEEB33A78B612AABDD6590CA4E609CC88906457787F13FF7"));
            PublicKey pubkey = kf.generatePublic(spec);
            secrets.getISAKMPSA().setDhKeyPair(new KeyPair(pubkey, privkey));
        }
        secrets.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("75cc633d664fd556"));
        secrets.getISAKMPSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("a3a34f453de42c67"));

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.Aggressive);
        msg.addPayload(sa);
        msg.addPayload(handshake.prepareKeyExchangePayload(new byte[4]));
        msg.addPayload(handshake.prepareNoncePayload(new byte[4]));
        msg.addPayload(handshake.prepareIdentificationPayload());
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("0534fc1813e089e1"), secrets.getResponderCookie());
        assertFalse(((HashPayload) answer.getPayloads().get(answer.getPayloads().size() - 1)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.Aggressive);
        msg.addPayload(handshake.preparePhase1HashPayload());
        answer = handshake.exchangeMessage(msg);

        assertNull(answer);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(DatatypeHelper.hexDumpToByteArray("e582bf04"));
        handshake.setMostRecentMessageID(msg.getMessageId());
        sa = SecurityAssociationPayloadFactory.P2_ESP_TUNNEL_AES128_SHA1;
        sa.getProposalPayloads().get(0).setSPI(DatatypeHelper.hexDumpToByteArray("f94d660a"));
        msg.addPayload(sa);
        secrets.getSA(msg.getMessageId()).setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("35496d7f0f01f56f"));
        msg.addPayload(handshake.prepareNoncePayload(msg.getMessageId()));
        IdentificationPayload id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.ID_IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.ID_IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        handshake.addPhase2Hash1Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("cc23d268"), ((SecurityAssociationPayload) answer.getPayloads().get(1)).getProposalPayloads().get(0).getSPI());
        assertFalse(((HashPayload) answer.getPayloads().get(0)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(handshake.getMostRecentMessageID());
        handshake.addPhase2Hash3Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertNull(answer);
    }

    @Test
    public void testMainModePSKHandshake() throws Exception {
        ISAKMPMessage msg, answer;
        SecurityAssociationPayload sa;

        sa = SecurityAssociationPayloadFactory.P1_PSK_AES128_SHA1_G2;
        handshake.adjustCiphersuite(sa);
        IKEv1HandshakeSessionSecrets secrets = handshake.secrets;
        secrets.generateDefaults();

        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        secrets.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("59cedc5dcea558fe"));

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.addPayload(sa);
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("9e16984236445257"), answer.getResponderCookie());
                
        secrets.getISAKMPSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("32ae9db36e7418a7"));
        {
            KeySpec spec = new PKCS8EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082012102010030819506092A864886F70D01030130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0201020481830281806F583CA64176389AE033076D036EA24BBE93F0D66A2C64A5ECA5E8F38A521CC5F040CEE069794C6DCB69165795060D4DF4C6CC7A6C64806DE7FA9852151816151E6099533761316FC040476793CF4C2B3A3BB0A96B324549B8FB6519CE22E6F110FC32EB304A155F703EFFE2D9A7082E910A3F3167F26A5C4A166D1A133CB07F"));
            KeyFactory kf = KeyFactory.getInstance("DH");
            PrivateKey privkey = kf.generatePrivate(spec);
            spec = new X509EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082011E30819306072A8648CE3E020130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0201020381850002818100B5FCEA14E2593EE937054B98886CA43B00472167DB154FF074E158E8B7FCAE77AC35CEF073698BFE63C99C6DD64AE25A95D55800A845A5DB0640D1C3EA5BB8596CB0FFA5D4DB0FD01E1875941B14AD4AC492FB5F6381DB934664AD8493FE95AAB7F1FF8976F329B5EA0F9EDE244E906FB419353E878F2FA92CCD533BA33D79EE"));
            PublicKey pubkey = kf.generatePublic(spec);
            secrets.getISAKMPSA().setDhKeyPair(new KeyPair(pubkey, privkey));
        }
        
        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.addPayload(handshake.prepareKeyExchangePayload(new byte[4]));
        msg.addPayload(handshake.prepareNoncePayload(new byte[4]));
        answer = handshake.exchangeMessage(msg);
        
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("ce2b9ff5f8519260b6c8f153529bc5a43121e3aa57a3de7d0d63baba86679e57"), ((NoncePayload) answer.getPayloads().get(answer.getPayloads().size() - 1)).getNonceData());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.setEncryptedFlag(true);
        msg.addPayload(handshake.prepareIdentificationPayload());
        msg.addPayload(handshake.preparePhase1HashPayload());
        answer = handshake.exchangeMessage(msg);
        
        assertFalse(((HashPayload) answer.getPayloads().get(answer.getPayloads().size() - 1)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(DatatypeHelper.hexDumpToByteArray("259cf133"));
        handshake.setMostRecentMessageID(msg.getMessageId());
        sa = SecurityAssociationPayloadFactory.P2_ESP_TUNNEL_AES128_SHA1;
        sa.getProposalPayloads().get(0).setSPI(DatatypeHelper.hexDumpToByteArray("b75ad16c"));
        msg.addPayload(sa);
        secrets.getSA(msg.getMessageId()).setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("695346ebcf35ab90"));
        msg.addPayload(handshake.prepareNoncePayload(msg.getMessageId()));
        IdentificationPayload id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.ID_IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.ID_IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        handshake.addPhase2Hash1Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("c6bf8b4d"), ((SecurityAssociationPayload) answer.getPayloads().get(1)).getProposalPayloads().get(0).getSPI());
        assertFalse(((HashPayload) answer.getPayloads().get(0)).isCheckFailed());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(handshake.getMostRecentMessageID());
        handshake.addPhase2Hash3Payload(msg);
        answer = handshake.exchangeMessage(msg);

        assertNull(answer);
    }
}
