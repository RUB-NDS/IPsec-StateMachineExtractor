/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationPayloadFactory;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPMessage;
import static de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPMessageTest.getTestIKEv1MainModeSecurityAssociationMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.NotificationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.NotifyMessageTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeTest {

    static {
        CryptoHelper.prepare();
    }

    /**
     * Test of prepareKeyExchangePayload method, of class IKEv1Handshake.
     */
    @Test
    public void testPrepareKeyExchangePayload() throws Exception {
        IKEv1Handshake instance = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        ISAKMPPayload result = instance.prepareKeyExchangePayload(new byte[4]);
        assertTrue(result.getLength() <= instance.ciphersuite.getDhGroup().getPublicKeySizeInBytes() + 4);
    }

    /**
     * Test of prepareKeyExchangePayload method, of class IKEv1Handshake.
     */
    @Test
    public void testPrepareKeyExchangePayloadEC() throws Exception {
        IKEv1Handshake instance = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        instance.ciphersuite.setDhGroup(DHGroupAttributeEnum.GROUP19);
        instance.secrets.generateDefaults();
        ISAKMPPayload result = instance.prepareKeyExchangePayload(new byte[4]);
        assertEquals(instance.ciphersuite.getDhGroup().getPublicKeySizeInBytes() + 4, result.getLength());
    }

    /**
     * Test of prepareNoncePayload method, of class IKEv1Handshake.
     */
    @Test
    public void testPrepareNoncePayload() throws Exception {
        IKEv1Handshake instance = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        ISAKMPPayload result = instance.prepareNoncePayload(new byte[4]);
        assertEquals(instance.ciphersuite.getNonceLen() + 4, result.getLength());
    }

    /**
     * Test of fromByteArray method, of class IKEv1MessageBuilder.
     */
    @Test
    public void testFromByteArray_IKEv1MainModeSecurityAssociationMessage() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        getTestIKEv1MainModeSecurityAssociationMessage().writeBytes(baos);
        IKEv1Handshake handshake = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        ISAKMPMessage instance = handshake.ISAKMPMessageFromByteArray(baos.toByteArray());
        assertEquals(1, instance.getPayloads().size());
    }

    /**
     * Test of fromByteArray method, of class IKEv1MessageBuilder.
     */
    @Test
    public void testFromByteArray_IKEv1PayloadMalformedNotification() throws Exception {
        byte[] wiresharkDump = DatatypeHelper.hexDumpToByteArray("00574fee41e8f80a3287d995d890aaed0b100500d9ac8bc0000000280000000c0000000101000010");
        IKEv1Handshake handshake = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        ISAKMPMessage instance = handshake.ISAKMPMessageFromByteArray(wiresharkDump);
        assertArrayEquals(DatatypeHelper.hexDumpToByteArray("3287d995d890aaed"), instance.getResponderCookie());
        assertEquals(ExchangeTypeEnum.Informational, instance.getExchangeType());
        assertEquals(1, instance.getPayloads().size());
        assertEquals(IKEPayloadTypeEnum.Notification, instance.getPayloads().get(0).getType());
        assertEquals(NotifyMessageTypeEnum.PayloadMalformed, ((NotificationPayload) instance.getPayloads().get(0)).getNotifyMessageType());
    }

    @Test
    @Ignore
    public void testAggressiveHandhake() throws Exception {
        IKEv1Handshake handshake = new IKEv1Handshake(500, InetAddress.getByName("10.0.3.10"), 500);
        SecurityAssociationPayload sa;
        ISAKMPMessage answer;

        ISAKMPMessage msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.Aggressive);
        sa = SecurityAssociationPayloadFactory.V1_P1_PSK_AES128_SHA1_G2;
        msg.addPayload(sa);
        handshake.adjustCiphersuite(sa);
        msg.addPayload(handshake.prepareKeyExchangePayload(new byte[4]));
        msg.addPayload(handshake.prepareNoncePayload(new byte[4]));
        System.out.println(DatatypeHelper.byteArrayToHexDump(handshake.secrets.getHandshakeSA().getDhKeyPair().getPrivate().getEncoded()));
        System.out.println(DatatypeHelper.byteArrayToHexDump(handshake.secrets.getHandshakeSA().getDhKeyPair().getPublic().getEncoded()));
        answer = handshake.exchangeMessage(msg);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.Aggressive);
        msg.addPayload(handshake.preparePhase1HashPayload());
        answer = handshake.exchangeMessage(msg);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageIdRandom();
        handshake.setMostRecentMessageID(msg.getMessageId());
        sa = SecurityAssociationPayloadFactory.getV1_P2_ESP_TUNNEL_AES128_SHA1();
        msg.addPayload(sa);
        msg.addPayload(handshake.prepareNoncePayload(msg.getMessageId()));
        IdentificationPayload id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(new byte[8]);
        msg.addPayload(id);
        handshake.addPhase2Hash1Payload(msg);
        answer = handshake.exchangeMessage(msg);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(handshake.getMostRecentMessageID());
        handshake.addPhase2Hash3Payload(msg);
        answer = handshake.exchangeMessage(msg);
    }

    @Test
    @Ignore
    public void testMainModeHandhake() throws Exception {
        IKEv1Handshake handshake = new IKEv1Handshake(1000, InetAddress.getByName("10.0.3.2"), 500);
        SecurityAssociationPayload sa;
        ISAKMPMessage answer;

        ISAKMPMessage msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        sa = SecurityAssociationPayloadFactory.V1_P1_PSK_AES128_SHA1_G2;
        msg.addPayload(sa);
        handshake.adjustCiphersuite(sa);
        answer = handshake.exchangeMessage(msg);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.addPayload(handshake.prepareKeyExchangePayload(new byte[4]));
        msg.addPayload(handshake.prepareNoncePayload(new byte[4]));
        System.out.println(DatatypeHelper.byteArrayToHexDump(handshake.secrets.getHandshakeSA().getDhKeyPair().getPrivate().getEncoded()));
        System.out.println(DatatypeHelper.byteArrayToHexDump(handshake.secrets.getHandshakeSA().getDhKeyPair().getPublic().getEncoded()));
        answer = handshake.exchangeMessage(msg);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.IdentityProtection);
        msg.setEncryptedFlag(true);
        msg.addPayload(handshake.prepareIdentificationPayload());
        msg.addPayload(handshake.preparePhase1HashPayload());
        answer = handshake.exchangeMessage(msg);
        System.out.println(answer.toString());

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageIdRandom();
        handshake.setMostRecentMessageID(msg.getMessageId());
        sa = SecurityAssociationPayloadFactory.getV1_P2_ESP_TUNNEL_AES128_SHA1();
        msg.addPayload(sa);
        msg.addPayload(handshake.prepareNoncePayload(msg.getMessageId()));
        IdentificationPayload id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(DatatypeHelper.hexDumpToByteArray("0a000100ffffff00"));
        msg.addPayload(id);
        id = new IdentificationPayload();
        id.setIdType(IDTypeEnum.IPV4_ADDR_SUBNET);
        id.setIdentificationData(DatatypeHelper.hexDumpToByteArray("0a000200ffffff00"));
        msg.addPayload(id);
        handshake.addPhase2Hash1Payload(msg);
        answer = handshake.exchangeMessage(msg);
        System.out.println(answer);
        assertFalse(answer.toString().contains("!"));

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageId(handshake.getMostRecentMessageID());
        handshake.addPhase2Hash3Payload(msg);
        answer = handshake.exchangeMessage(msg);
    }
}
