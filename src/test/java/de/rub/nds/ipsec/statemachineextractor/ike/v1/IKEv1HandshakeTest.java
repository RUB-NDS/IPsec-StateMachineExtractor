/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import static de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessageTest.getTestIKEv1MainModeSecurityAssociationMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NotificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NotifyMessageTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;
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
        KeyExchangePayload result = instance.prepareKeyExchangePayload(new byte[4]);
        assertTrue(result.getLength() <= instance.ciphersuite.getDhGroup().getDHGroupParameters().getPublicKeySizeInBytes() + 4);
    }

    /**
     * Test of prepareKeyExchangePayload method, of class IKEv1Handshake.
     */
    @Test
    public void testPrepareKeyExchangePayloadEC() throws Exception {
        IKEv1Handshake instance = new IKEv1Handshake(0, InetAddress.getLocalHost(), 500);
        instance.ciphersuite.setDhGroup(DHGroupAttributeEnum.GROUP19);
        instance.secrets.generateDefaults();
        KeyExchangePayload result = instance.prepareKeyExchangePayload(new byte[4]);
        assertEquals(instance.ciphersuite.getDhGroup().getDHGroupParameters().getPublicKeySizeInBytes() + 4, result.getLength());
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
        assertEquals(PayloadTypeEnum.Notification, instance.getPayloads().get(0).getType());
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
        sa = SecurityAssociationPayloadFactory.P1_PSK_AES128_SHA1_G2;
        msg.addPayload(sa);
        handshake.adjustCiphersuite(sa);
        msg.addPayload(handshake.prepareKeyExchangePayload(new byte[4]));
        msg.addPayload(handshake.prepareNoncePayload(new byte[4]));
        msg.addPayload(handshake.prepareIdentificationPayload());
        answer = handshake.exchangeMessage(msg);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.Aggressive);
        msg.addPayload(handshake.preparePhase1HashPayload());
        answer = handshake.exchangeMessage(msg);

        msg = new ISAKMPMessage();
        msg.setExchangeType(ExchangeTypeEnum.QuickMode);
        msg.setEncryptedFlag(true);
        msg.setMessageIdRandom();
        sa = SecurityAssociationPayloadFactory.P2_ESP_TUNNEL_AES128_SHA1;
        msg.addPayload(sa);
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
        answer.toString();
    }
}
