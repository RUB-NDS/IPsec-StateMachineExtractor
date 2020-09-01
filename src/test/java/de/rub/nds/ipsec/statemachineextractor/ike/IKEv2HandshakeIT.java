/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationPayloadFactory;
import de.rub.nds.ipsec.statemachineextractor.ike.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshake;
import de.rub.nds.ipsec.statemachineextractor.ike.NotifyMessageTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2HandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.EncryptedIKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.EncryptedIKEv2MessageMock;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.EncryptedPayloadMock;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.NotificationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.SecurityAssociationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.networking.LoquaciousClientUdpTransportHandler;
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
import javax.crypto.spec.SecretKeySpec;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.Before;

/**
 * Integration tests that mock a responder and replay recorded handshakes.
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2HandshakeIT {

    static {
        CryptoHelper.prepare();
    }

    IKEHandshake handshake;
    HashMap<String, String> msgPairs = new HashMap<>();

    public IKEv2HandshakeIT() {
        // IKE_SA_INIT m1 / m2
        msgPairs.put("a150f12f598f9a0e00000000000000002120220800000000000000e8220000300000002c010100040300000c0100000c800e00800300000802000002030000080300000200000008040000022800008800020000fb7f97f9f4eca31f7ac9ba0516f8e616977bf606ab295295e6615ef91e8a15b4ad18940a448248ddf31c95415e5525050ee8803a084a0707733f8833eb9c5cdf1ad55062f06c234856d7a580ba883bc8d7a864175708d59bec0c3bcd21acc495ca5b311167be6245222c168417d4a613b3ca04f961d7335ad13073e2279f542e00000014828755ecab3d7b8c1a20126dbcb078b3",
                "a150f12f598f9a0e9fb14c9c853ad1b2212022200000000000000100220000300000002c010100040300000c0100000c800e00800300000803000002030000080200000200000008040000022800008800020000c581b93b78222b7ed4b70cf36f0c1016d010695beedee8ceb55ead79380f20b3692ee6ca7ea33a4a89b0976bed9b829f92a81d2d68a07992b52f2bf7f58968b3b064e9ba588259766db1dcf266f6563a81b364853d916ec3d22d4e9391ece402fb68b5cbd6aa8297cf747116a2bdcfb6029c9a192928062925269bcd50d3d64f29000024f03a7ef00422adb77cecd38214ee50bb9cde6519639c3faa63d3345a1b82e1f10000000800004014");
        // IKE_AUTH m3 / m4
        msgPairs.put("a150f12f598f9a0e9fb14c9c853ad1b22e20230800000001000000cc230000b02bb84e27d979e2342446d5d9cff1bafb136607c998c9fc1ff199ff1b2c38dc4eef44ad7712a9174945083b0862774f79c5a92ae2889823bca2cf7738e1d977b2d34021479323988dcd48d40959678a364de324688aadde6be417698414a0ac0442759762ee2a34570efd79a0425e1a8ae261073b587ee4a5a719ea6bc87d53799da221bbebde2048fdcc4d9ca26f468441916be99487517d67e96902b917b6afdccb478adbfb818dd90760f5",
                "a150f12f598f9a0e9fb14c9c853ad1b22e20232000000001000000cc240000b0a7188784512abc1324e1afb326db055a72e6a474e7caea11918feed8da60ea76b272dd6093ed6424189dc57e7e961dc5bee67c68594b816e48ec30b253287bb9ac1f2fac67b8ece47161f56662b0eed973e219466491358ea935669dd1ee3ce587e6e2e4dfff227478ef1a36a9f812a68d191cfb919a60b2e071f49d904cc1092dbeadee318782d1097a667ad712d95c8dc00edf209897ff39c077d3f7550f4c93451af1126aee3a391eed81");
    }

    @Before
    public void setUp() throws Exception {
        handshake = new IKEHandshake(0, InetAddress.getLocalHost(), 500);
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
    public void testSimulatedHandshake() throws Exception {
        IKEv2Message msg;
        IKEMessage answer;
        SecurityAssociationPayloadv2 sa;

        sa = SecurityAssociationPayloadFactory.V2_P1_AES_128_CBC_SHA1;
        IKEv2HandshakeSessionSecrets secrets = handshake.secrets_v2;
        secrets.generateDefaults();

        handshake.ltsecrets.setPreSharedKey("AAAA".getBytes());
        {
            KeySpec spec = new PKCS8EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082012202010030819506092A864886F70D01030130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF02010204818402818100CA6B37206E30A93456570623C38627769C980D8CD011C4DFFFF39B1684757083B733DDAA7C47536EDCAF1E2271382C8BDB1D114D2E7A4C6165E685F903B6179115B1B7A1B0C8055511004C0364C58BFEF2E1E2E1D22CC5FF71AF0664C657E22F51BD4F5CDAE5CEB5512A23261065BC689AE407188259ABD04814E6667A2A2F82"));
            KeyFactory kf = KeyFactory.getInstance("DH");
            PrivateKey privkey = kf.generatePrivate(spec);
            spec = new X509EncodedKeySpec(DatatypeHelper.hexDumpToByteArray("3082011E30819306072A8648CE3E020130818702818100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF0201020381850002818100FB7F97F9F4ECA31F7AC9BA0516F8E616977BF606AB295295E6615EF91E8A15B4AD18940A448248DDF31C95415E5525050EE8803A084A0707733F8833EB9C5CDF1AD55062F06C234856D7A580BA883BC8D7A864175708D59BEC0C3BCD21ACC495CA5B311167BE6245222C168417D4A613B3CA04F961D7335AD13073E2279F542E"));
            PublicKey pubkey = kf.generatePublic(spec);
            secrets.getHandshakeSA().setDhKeyPair(new KeyPair(pubkey, privkey));
        }
        secrets.setInitiatorCookie(DatatypeHelper.hexDumpToByteArray("a150f12f598f9a0e"));
        secrets.getHandshakeSA().setInitiatorNonce(DatatypeHelper.hexDumpToByteArray("828755ecab3d7b8c1a20126dbcb078b3"));

        msg = new IKEv2Message();
        byte[] msgID = DatatypeHelper.hexDumpToByteArray("00000000");
        msg.setExchangeType(ExchangeTypeEnum.IKE_SA_INIT);
        msg.setInitiatorFlag(true);
        msg.setVersionFlag(false);
        msg.setResponseFlag(false);
        msg.addPayload(sa);
        //handshake.adjustCiphersuite(sa);
        msg.addPayload(handshake.prepareIKEv2KeyExchangePayload(msgID));
        msg.addPayload(handshake.prepareIKEv2NoncePayload(msgID));
        answer = handshake.exchangeMessage(msg);

        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("9fb14c9c853ad1b2"), secrets.getResponderCookie());
        assertEquals(NotifyMessageTypeEnum.MultipleAuthSupport, ((NotificationPayloadv2) answer.getPayloads().get(3)).getNotifyMessageType());

        msg = new IKEv2Message();
        msgID = DatatypeHelper.hexDumpToByteArray("00000001");
        msg.setMessageId(msgID);
        msg.setExchangeType(ExchangeTypeEnum.IKE_AUTH);
        msg.setInitiatorFlag(true);
        msg.setVersionFlag(false);
        msg.setResponseFlag(false);
        handshake.secrets_v2.setMessage(handshake.messages.get(0).getMessage().getBytes());
        msg.addPayload(handshake.prepareIKEv2IdentificationInitiator());
        handshake.secrets_v2.computeOctets();
        msg.addPayload(handshake.prepareIKEv2AuthenticationPayload());
        sa = SecurityAssociationPayloadFactory.V2_P2_AES_128_CBC_SHA1_ESN;
        sa.getProposalPayloads().get(0).setSPI(DatatypeHelper.hexDumpToByteArray("2a85e115"));
        msg.addPayload(sa);
        msg.addPayload(handshake.prepareIKEv2TrafficSelectorPayloadInitiator());
        msg.addPayload(handshake.prepareIKEv2TrafficSelectorPayloadResponder());
        SecretKeySpec ENCRkey = new SecretKeySpec(handshake.secrets_v2.getSKei(), handshake.ciphersuite_v2.getCipher().cipherJCEName());
        handshake.secrets_v2.setIV(msgID, DatatypeHelper.hexDumpToByteArray("2BB84E27D979E2342446D5D9CFF1BAFB"));
        byte[] iv = handshake.secrets_v2.getIV(msgID);
        EncryptedIKEv2Message ENCmsg = EncryptedIKEv2MessageMock.fromPlainMessage(msg, ENCRkey, handshake.ciphersuite_v2.getCipher(), iv, handshake.secrets_v2.getSKai(), handshake.ciphersuite_v2.getAuthMethod());
        EncryptedPayloadMock ENCRPayload = new EncryptedPayloadMock();
        ENCRPayload.setIV(((EncryptedIKEv2MessageMock)ENCmsg).getENCRPayload().getIV());
        ENCRPayload.setPresetPadding(DatatypeHelper.hexDumpToByteArray("689EDB13A9EC81374F4C7C"));
        ((EncryptedIKEv2MessageMock)ENCmsg).setENCRPayload(ENCRPayload);
        answer = handshake.exchangeMessage(ENCmsg);

//        TODO: Check parsing of message
//        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("cc23d268"), ((SecurityAssociationPayload) answer.getPayloads().get(1)).getProposalPayloads().get(0).getSPI());
//        assertFalse(((HashPayload) answer.getPayloads().get(0)).isCheckFailed());
    }
}
