/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2;

import de.rub.nds.ipsec.statemachineextractor.WireMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ike.HandshakeLongtermSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationPayloadFactory;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IdentificationPayloadInitiator;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.AuthenticationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.AuthMethodEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.EncryptedIKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.TrafficSelectorPayloadResponder;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.TrafficSelectorPayloadInitiator;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.NotificationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.KeyExchangePayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.NoncePayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IKEv2Payload;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.SecurityAssociationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.networking.LoquaciousClientUdpTransportHandler;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IKEv2Handshake {

    LoquaciousClientUdpTransportHandler udpTH;
    IKEv2Ciphersuite ciphersuite;
    HandshakeLongtermSecrets ltsecrets;
    IKEv2HandshakeSessionSecrets secrets;
    List<WireMessage> messages = new ArrayList<>();
    final long timeout;
    final InetAddress remoteAddress;
    final int remotePort;

    public IKEv2Handshake(long timeout, InetAddress remoteAddress, int remotePort) throws IOException, GeneralSecurityException {
        this.timeout = timeout;
        this.remoteAddress = remoteAddress;
        this.remotePort = remotePort;
        reset();
    }

    protected byte[] exchangeData(byte[] txData) throws IOException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        udpTH.sendData(txData);
        byte[] rxData = udpTH.fetchData();
        if (rxData.length == 0) {
            return null;
        }
        Set<ByteBuffer> rxMsgs = messages.stream().filter(wm -> wm.isSentByMe() == false).map(WireMessage::getData).collect(Collectors.toSet());
        if (rxMsgs.contains(ByteBuffer.wrap(rxData))) {
            return null; //only a retransmission
        }
        return rxData;
    }

    public IKEv2Message exchangeMessage(IKEv2Message messageToSend) throws IOException, GenericIKEParsingException, GeneralSecurityException, IKEHandshakeException {
        if (secrets.getInitiatorCookie() == null) {
            secrets.setInitiatorCookie(messageToSend.getInitiatorCookie());
        } else {
            messageToSend.setInitiatorCookie(secrets.getInitiatorCookie());
        }
        messageToSend.setResponderCookie(secrets.getResponderCookie());
        if (messageToSend.getNextPayload() == IKEPayloadTypeEnum.SecurityAssociationv2 && secrets.getHandshakeSA().getSAOfferBody() == null) {
            secrets.getHandshakeSA().setSAOfferBody(messageToSend.getPayloads().get(0).getBody());
        }
        byte[] txData = messageToSend.getBytes();
        messages.add(new WireMessage(txData, messageToSend, true));
        byte[] rxData = exchangeData(txData);
        if (rxData == null) {
            return null;
        }
        IKEv2Message messageReceived = IKEv2MessageFromByteArray(rxData);
        messages.add(new WireMessage(rxData, messageReceived, false));
        return messageReceived;
    }

    IKEv2Message IKEv2MessageFromByteArray(byte[] bytes) throws GenericIKEParsingException, GeneralSecurityException, IKEHandshakeException, IOException {
        if (bytes.length < IKEv2Message.HEADER_LEN) {
            throw new IKEv2ParsingException("Not enough bytes supplied to build an IKEv2Message!");
        }
        switch (ExchangeTypeEnum.get(bytes[18])) {
            case IKE_SA_INIT:
            case IKE_AUTH:
                break;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
        IKEv2Message message = new IKEv2Message();
        message.setInitiatorCookie(Arrays.copyOfRange(bytes, 0, 8));
        message.setResponderCookie(Arrays.copyOfRange(bytes, 8, 16));
        message.setVersion(bytes[17]);
        message.setExchangeType(ExchangeTypeEnum.get(bytes[18]));
        message.setInitiatorFlag((bytes[19] & 8) > 0);
        message.setVersionFlag(false);
        message.setResponseFlag((bytes[19] & 32) > 0);
        message.setMessageId(Arrays.copyOfRange(bytes, 20, 24));
        int messageLength = new BigInteger(Arrays.copyOfRange(bytes, 24, 28)).intValue();
        secrets.setResponderCookie(message.getResponderCookie());

        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        bais.skip(IKEv2Message.HEADER_LEN);
        IKEPayloadTypeEnum nextPayload = IKEPayloadTypeEnum.get(bytes[16]);
        if (nextPayload == IKEPayloadTypeEnum.EncryptedAndAuthenticated) {
            processEncryptedMessage(message, nextPayload, bais);
        } else {
            processPlainMessage(message, nextPayload, bais);
        }
        //if (messageLength != message.getLength()) {
        //  throw new IKEv2ParsingException("Message lengths differ - Computed: " + message.getLength() + " vs. Received: " + messageLength + "!");
        //}
        return message;
    }

    private IKEv2Message processEncryptedMessage(IKEv2Message encMessage, IKEPayloadTypeEnum nextPayload, ByteArrayInputStream bais) throws GeneralSecurityException, GenericIKEParsingException, IKEHandshakeException {
        SecretKeySpec ENCRkey = new SecretKeySpec(secrets.getSKer(), ciphersuite.getCipher().cipherJCEName());
        byte[] iv = secrets.getIV(encMessage.getMessageId());
        byte[] INTEGkey = secrets.getSKar();
        EncryptedIKEv2Message decMessage = EncryptedIKEv2Message.fromPlainMessage(encMessage, ENCRkey, ciphersuite.getCipher(), iv, INTEGkey, ciphersuite.getAuthMethod());
        decMessage.setCiphertext(bais);
        decMessage.setNextPayload(nextPayload);
        decMessage.decrypt();
        //return decMessage;
        return null;
    }

    private void processPlainMessage(IKEv2Message message, IKEPayloadTypeEnum nextPayload, ByteArrayInputStream bais) throws GenericIKEParsingException, GeneralSecurityException, IllegalStateException, UnsupportedOperationException, IKEHandshakeException, IOException {
        IKEv2Payload payload;
        while (nextPayload != IKEPayloadTypeEnum.NONE) {
            switch (nextPayload) {
                case SecurityAssociationv2:
                    payload = SecurityAssociationPayloadv2.fromStream(bais);
                    SecurityAssociationPayloadv2 receivedSAPayload = (SecurityAssociationPayloadv2) payload;
                    //adjustCiphersuite(receivedSAPayload);
                    break;
                case KeyExchangev2:
                    switch (ciphersuite.getAuthMethod()) {
                        //case MD5:
                        default:
                            payload = KeyExchangePayloadv2.fromStream(bais);
                            secrets.getHandshakeSA().setPeerKeyExchangeData(((KeyExchangePayloadv2) payload).getKeyExchangeData());
                            break;
                    }
                    secrets.getHandshakeSA().computeDHSecret();
                    break;
                case Noncev2:
                    switch (ciphersuite.getAuthMethod()) {
                    	//case MD5:
                        default:
                            payload = NoncePayloadv2.fromStream(bais);
                            secrets.getHandshakeSA().setResponderNonce(((NoncePayloadv2) payload).getNonceData());
                            break;
                    }
                    secrets.computeSecretKeys();
                    break;
                /*
                case VendorID:
                    payload = VendorIDPayload.fromStream(bais);
                    break;
                 */
                case Notify:
                    payload = NotificationPayloadv2.fromStream(bais);
                    break;
                default:
                    throw new UnsupportedOperationException("Not supported yet.");
            }
            nextPayload = payload.getNextPayload();
            message.addPayload(payload);
        }
    }

    public void reset() throws IOException, GeneralSecurityException {
        messages.clear();
        ciphersuite = new IKEv2Ciphersuite();
        ltsecrets = new HandshakeLongtermSecrets();
        secrets = new IKEv2HandshakeSessionSecrets(ciphersuite, ltsecrets);
        if (this.udpTH != null) {
            dispose();
        }
        this.udpTH = new LoquaciousClientUdpTransportHandler(this.timeout, this.remoteAddress.getHostAddress(), this.remotePort);
        //prepareIdentificationPayload(); // sets secrets.identificationPayloadBody
        //secrets.setPeerIdentificationPayloadBody(secrets.getIdentificationPayloadBody()); // only a default
        //secrets.getHandshakeSA().setSAOfferBody(null);
        secrets.generateDefaults();
    }

    public IKEv2Message Phase1() throws IOException, GeneralSecurityException, GenericIKEParsingException, IKEHandshakeException {
        byte[] msgID = DatatypeHelper.hexDumpToByteArray("00000000");
        IKEv2Message msg = new IKEv2Message();
        IKEv2Payload SAv2 = preparePhase1SecurityAssociation();
        IKEv2Payload KEv2 = prepareKeyExchangePayload(msgID);
        IKEv2Payload NOv2 = prepareNoncePayload(msgID);
        msg.addPayload(SAv2);
        msg.addPayload(KEv2);
        msg.addPayload(NOv2);
        msg.setExchangeType(ExchangeTypeEnum.IKE_SA_INIT);
        msg.setInitiatorFlag(true);
        msg.setVersionFlag(false);
        msg.setResponseFlag(false);
        return exchangeMessage(msg);
    }

    public IKEv2Message Phase2() throws IOException, GeneralSecurityException, GenericIKEParsingException, IKEHandshakeException {
        byte[] msgID = DatatypeHelper.hexDumpToByteArray("00000001"); //implement as messages divided by 2
        secrets.setMessage(messages.get(0).getMessage().getBytes());
        IKEv2Message msg = new IKEv2Message();
        IKEv2Payload IDinit = prepareIdentificationInitiator();
        secrets.computeOctets();
        IKEv2Payload AUTH = prepareAuthenticationPayload();
        IKEv2Payload SA2 = preparePhase2SecurityAssociation();
        IKEv2Payload TSi = prepareTrafficSelectorPayloadInitiator();
        IKEv2Payload TSr = prepareTrafficSelectorPayloadResponder();
        msg.addPayload(IDinit);
        msg.addPayload(AUTH);
        msg.addPayload(SA2);
        msg.addPayload(TSi);
        msg.addPayload(TSr);
        msg.setMessageId(msgID);
        msg.setExchangeType(ExchangeTypeEnum.IKE_AUTH);
        msg.setInitiatorFlag(true);
        msg.setVersionFlag(false);
        msg.setResponseFlag(false);
        SecretKeySpec ENCRkey = new SecretKeySpec(secrets.getSKei(), ciphersuite.getCipher().cipherJCEName());
        byte[] iv = secrets.getIV(msgID);
        EncryptedIKEv2Message ENCmsg = EncryptedIKEv2Message.fromPlainMessage(msg, ENCRkey, ciphersuite.getCipher(), iv, secrets.getSKai(), ciphersuite.getAuthMethod());
        return exchangeMessage(ENCmsg);
    }

    public void dispose() throws IOException {
        if (udpTH.isInitialized()) {
            udpTH.closeConnection();
        }
    }

    public IKEv2Payload preparePhase1SecurityAssociation() {
        return SecurityAssociationPayloadFactory.V2_P1_AES_128_CBC_SHA1;
    }

    public IKEv2Payload preparePhase2SecurityAssociation() {
        return SecurityAssociationPayloadFactory.V2_P2_AES_128_CBC_SHA1_ESN;
    }

    public byte[] getMostRecentMessageID() {
        return secrets.getMostRecentMessageID();
    }

    public void setMostRecentMessageID(byte[] mostRecentMessageID) {
        secrets.setMostRecentMessageID(mostRecentMessageID);
    }

    public IKEv2Payload prepareKeyExchangePayload(byte[] msgID) throws GeneralSecurityException, IKEv2ParsingException {
        SecurityAssociationSecrets sas = this.secrets.getSA(msgID);
        KeyExchangePayloadv2 result = new KeyExchangePayloadv2(sas.getDHGroup());
        //System.out.println(new String(sas.generateKeyExchangeData(), 0));
        result.setKeyExchangeData(sas.generateKeyExchangeData());
        result.configureBody();
        return result;
    }

    public IKEv2Payload prepareNoncePayload(byte[] msgID) throws GeneralSecurityException {
        NoncePayloadv2 result = new NoncePayloadv2();
        SecurityAssociationSecrets sas = this.secrets.getSA(msgID);
        if (sas.getInitiatorNonce() == null) {
            SecureRandom random = new SecureRandom();
            byte[] initiatorNonce = new byte[ciphersuite.getNonceLen()];
            random.nextBytes(initiatorNonce);
            sas.setInitiatorNonce(initiatorNonce);
        }
        result.setNonceData(sas.getInitiatorNonce());
        return result;
    }

    public IdentificationPayloadInitiator prepareIdentificationInitiator() throws IOException {
        InetAddress addr = udpTH.getLocalAddress();
        IdentificationPayloadInitiator result = new IdentificationPayloadInitiator();
        result.setIdType(IDTypeEnum.IPV4_ADDR);
        result.setIdentificationData(addr.getAddress());
        result.setIDi();
        secrets.setIDi(result.getIDi());
        return result;
    }

    public AuthenticationPayload prepareAuthenticationPayload() throws GeneralSecurityException {
        AuthenticationPayload result = new AuthenticationPayload();
        result.setAuthMethod(AuthMethodEnum.PSK);
        result.setAuthenticationData(secrets.computeAUTH());
        return result;
    }

    public TrafficSelectorPayloadInitiator prepareTrafficSelectorPayloadInitiator() {
        TrafficSelectorPayloadInitiator result = new TrafficSelectorPayloadInitiator();
        return result;
    }

    public TrafficSelectorPayloadResponder prepareTrafficSelectorPayloadResponder() {
        TrafficSelectorPayloadResponder result = new TrafficSelectorPayloadResponder();
        return result;
    }
}
