/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike;

import de.rub.nds.ipsec.statemachineextractor.WireMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.DeletePayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.EncryptedISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.PKCS1EncryptedISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1HandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SymmetricallyEncryptedISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SymmetricallyEncryptedIdentificationPayloadHuaweiStyle;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2Ciphersuite;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2HandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2ParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.AuthMethodEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.AuthenticationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.DHGroupTransformEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.EncryptedIKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IKEv2Payload;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IdentificationPayloadInitiator;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.KeyExchangePayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.NoncePayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.SecurityAssociationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.TrafficSelectorInitiatorPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.TrafficSelectorPayloadResponder;
import de.rub.nds.ipsec.statemachineextractor.networking.LoquaciousClientUdpTransportHandler;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
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
public class IKEHandshake {

    LoquaciousClientUdpTransportHandler udpTH;
    HandshakeLongtermSecrets ltsecrets;
    IKEv1Ciphersuite ciphersuite_v1;
    IKEv2Ciphersuite ciphersuite_v2;
    IKEv1HandshakeSessionSecrets secrets_v1;
    IKEv2HandshakeSessionSecrets secrets_v2;
    int nextv2MessageID = 0;
    List<WireMessage> messages = new ArrayList<>();
    final long timeout;
    final InetAddress remoteAddress;
    final int remotePort;

    public IKEHandshake(long timeout, InetAddress remoteAddress, int remotePort) throws IOException, GeneralSecurityException {
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

    public IKEMessage exchangeMessage(IKEMessage messageToSend) throws IOException, GenericIKEParsingException, GeneralSecurityException, IKEHandshakeException {
        byte[] initiatorCookie;
        IKEMessage messageReceived;
        if (secrets_v1.getInitiatorCookie() == null && secrets_v2.getInitiatorCookie() == null) {
            initiatorCookie = messageToSend.getInitiatorCookie(); // gets random cookie
        } else if (secrets_v1.getInitiatorCookie() != null) {
            initiatorCookie = secrets_v1.getInitiatorCookie();
        } else { // secrets_v2.getInitiatorCookie() != null
            initiatorCookie = secrets_v2.getInitiatorCookie();
        }
        secrets_v1.setInitiatorCookie(initiatorCookie);
        secrets_v2.setInitiatorCookie(initiatorCookie);
        messageToSend.setInitiatorCookie(initiatorCookie);
        messageToSend.setResponderCookie(secrets_v1.getResponderCookie());

        if (messageToSend instanceof ISAKMPMessage) {
            messageToSend = prepareISAKMPMessageForSending((ISAKMPMessage) messageToSend);
        } else if (messageToSend instanceof IKEv2Message) {
            messageToSend = prepareIKEv2MessageForSending((IKEv2Message) messageToSend);
        } else {
            throw new UnsupportedOperationException("Not supported.");
        }

        byte[] txData = messageToSend.getBytes();
        messages.add(new WireMessage(txData, messageToSend, true));
        byte[] rxData = exchangeData(txData);
        if (rxData == null) {
            return null;
        }

        //received an answer, so store necessary stuff
        secrets_v2.setMessage(txData);
        nextv2MessageID += 1;
        if ((messageToSend instanceof ISAKMPMessage) && ((ISAKMPMessage) messageToSend).isEncryptedFlag()) {
            //store last ciphertext block as IV for decryption
            secrets_v1.setIV(messageToSend.getMessageId(), ((EncryptedISAKMPMessage) messageToSend).getNextIV());
        }
        messageReceived = IKEMessageFromByteArray(rxData);
        if ((messageToSend instanceof ISAKMPMessage) && ((ISAKMPMessage) messageToSend).isEncryptedFlag()) {
            //message could be unmarshalled, so store last ciphertext block as IV for next encryption
            secrets_v1.setIV(messageReceived.getMessageId(), Arrays.copyOfRange(rxData, rxData.length - ciphersuite_v1.getCipher().getBlockSize(), rxData.length));
        }
        messages.add(new WireMessage(rxData, messageReceived, false));
        return messageReceived;
    }

    protected IKEMessage IKEMessageFromByteArray(byte[] bytes) throws GenericIKEParsingException, UnsupportedOperationException, IOException, GeneralSecurityException {
        if (bytes.length < IKEMessage.IKE_MESSAGE_HEADER_LEN) {
            throw new ISAKMPParsingException("Not enough bytes supplied to build an ISAKMPMessage!");
        }
        IKEMessage messageReceived;
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        switch (bytes[17]) {
            case ISAKMPMessage.VERSION:
                messageReceived = new ISAKMPMessage();
                try {
                    messageReceived.processFromStream(bais, ciphersuite_v1, secrets_v1, ltsecrets);
                } catch (ISAKMPMessage.IsEncryptedException ex) {
                    SecretKeySpec key = new SecretKeySpec(secrets_v1.getKa(), ciphersuite_v1.getCipher().cipherJCEName());
                    byte[] iv = secrets_v1.getIV(messageReceived.getMessageId());
                    messageReceived = new EncryptedISAKMPMessage(key, ciphersuite_v1.getCipher(), iv);
                    messageReceived.processFromStream(bais, ciphersuite_v1, secrets_v1, ltsecrets);
                }
                break;
            case IKEv2Message.VERSION:
                messageReceived = new IKEv2Message();
                try {
                    messageReceived.processFromStream(bais, ciphersuite_v2, secrets_v2, ltsecrets);
                } catch (IKEv2Message.IsEncryptedException ex) {
                    SecretKeySpec ENCRkey = new SecretKeySpec(secrets_v2.getSKer(), ciphersuite_v2.getCipher().cipherJCEName());
                    byte[] iv = secrets_v2.getIV(messageReceived.getMessageId());
                    byte[] INTEGkey = secrets_v2.getSKar();
                    messageReceived = new EncryptedIKEv2Message(ENCRkey, ciphersuite_v2.getCipher(), iv, INTEGkey, ciphersuite_v2.getAuthMethod());
                    messageReceived.processFromStream(bais, ciphersuite_v2, secrets_v2, ltsecrets);
                }
                break;
            default:
                throw new UnsupportedOperationException("Not supported.");
        }
        secrets_v1.setResponderCookie(messageReceived.getResponderCookie());
        secrets_v2.setResponderCookie(messageReceived.getResponderCookie());
        return messageReceived;
    }

    protected ISAKMPMessage prepareISAKMPMessageForSending(ISAKMPMessage messageToSend) throws GeneralSecurityException {
        if (messageToSend.isEncryptedFlag()) {
            messageToSend = EncryptedISAKMPMessage.fromPlainMessage(messageToSend, new SecretKeySpec(secrets_v1.getKa(), ciphersuite_v1.getCipher().cipherJCEName()), ciphersuite_v1.getCipher(), secrets_v1.getIV(messageToSend.getMessageId()));
        }
        if (messageToSend.getNextPayload() == IKEPayloadTypeEnum.SecurityAssociation && secrets_v1.getHandshakeSA().getSAOfferBody() == null) {
            secrets_v1.getHandshakeSA().setSAOfferBody(messageToSend.getPayloads().get(0).getBody());
        }
        return messageToSend;
    }

    protected IKEv2Message prepareIKEv2MessageForSending(IKEv2Message messageToSend) throws GeneralSecurityException {
        messageToSend.setMessageId(getNextv2MessageID());
        if (messageToSend.getExchangeType() != ExchangeTypeEnum.IKE_SA_INIT) {
            SecretKeySpec ENCRkey = new SecretKeySpec(secrets_v2.getSKei(), ciphersuite_v2.getCipher().cipherJCEName());
            byte[] iv = secrets_v2.getIV(getNextv2MessageID());
            messageToSend = EncryptedIKEv2Message.fromPlainMessage(messageToSend, ENCRkey, ciphersuite_v2.getCipher(), iv, secrets_v2.getSKai(), ciphersuite_v2.getAuthMethod());
        }
        if (messageToSend.getNextPayload() == IKEPayloadTypeEnum.SecurityAssociationv2 && secrets_v2.getHandshakeSA().getSAOfferBody() == null) {
            secrets_v2.getHandshakeSA().setSAOfferBody(messageToSend.getPayloads().get(0).getBody());
        }
        return messageToSend;
    }

    public void reset() throws IOException, GeneralSecurityException {
        messages.clear();
        ltsecrets = new HandshakeLongtermSecrets();
        ciphersuite_v1 = new IKEv1Ciphersuite();
        ciphersuite_v2 = new IKEv2Ciphersuite();
        secrets_v1 = new IKEv1HandshakeSessionSecrets(ciphersuite_v1, ltsecrets);
        secrets_v2 = new IKEv2HandshakeSessionSecrets(ciphersuite_v2, ltsecrets);
        if (this.udpTH != null) {
            dispose();
        }
        this.udpTH = new LoquaciousClientUdpTransportHandler(this.timeout, this.remoteAddress.getHostAddress(), this.remotePort);
        prepareIKEv1IdentificationPayload(); // sets secrets_v1.identificationPayloadBody
        secrets_v1.setPeerIdentificationPayloadBody(secrets_v1.getIdentificationPayloadBody()); // only a default
        secrets_v1.getHandshakeSA().setSAOfferBody(null);
        secrets_v1.generateDefaults();
        secrets_v2.generateDefaults();
    }

    public void dispose() throws IOException {
        if (udpTH.isInitialized()) {
            udpTH.closeConnection();
        }
    }

    public byte[] getMostRecentMessageID() {
        return secrets_v1.getMostRecentMessageID();
    }

    public void setMostRecentMessageID(byte[] mostRecentMessageID) {
        secrets_v1.setMostRecentMessageID(mostRecentMessageID);
    }

    public SecurityAssociationSecrets getMostRecentSecurityAssociation() {
        return secrets_v1.getSA(secrets_v1.getMostRecentMessageID());
    }

    public void computeIPsecKeyMaterial(SecurityAssociationSecrets sas) throws GeneralSecurityException {
        secrets_v1.computeKeyMaterial(sas);
    }

    public SecurityAssociationSecrets addInboundSPIAndProtocolToIPsecSecurityAssociation(SecurityAssociationPayload payload) throws GeneralSecurityException, IKEHandshakeException {
        if (payload.getProposalPayloads().size() != 1) {
            throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
        }
        ProposalPayload pp = payload.getProposalPayloads().get(0);
        SecurityAssociationSecrets sas = this.getMostRecentSecurityAssociation();
        sas.setInboundSpi(pp.getSPI());
        sas.setProtocol(pp.getProtocolId());
        return sas;
    }

    public ISAKMPPayload prepareIKEv1KeyExchangePayload(byte[] msgID) throws GeneralSecurityException {
        KeyExchangePayload result = new KeyExchangePayload();
        SecurityAssociationSecrets sas = this.secrets_v1.getSA(msgID);
        result.setKeyExchangeData(sas.generateKeyExchangeData());
        if (ciphersuite_v1.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            // this authentication method encrypts the key exchange value using a derived key
            secrets_v1.computeSecretKeys();
            SymmetricallyEncryptedISAKMPPayload rpke = new SymmetricallyEncryptedISAKMPPayload(result, ciphersuite_v1, new SecretKeySpec(secrets_v1.getKe_i(), ciphersuite_v1.getCipher().cipherJCEName()), secrets_v1.getRPKEIV());
            rpke.encrypt();
            secrets_v1.setRPKEIV(rpke.getNextIV());
            return rpke;
        }
        return result;
    }

    public ISAKMPPayload prepareIKEv1IdentificationPayload() throws IOException, GeneralSecurityException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        InetAddress addr = udpTH.getLocalAddress();
        IdentificationPayload result = new IdentificationPayload();
        if (addr instanceof Inet6Address) {
            result.setIdType(IDTypeEnum.IPV6_ADDR);
        } else if (addr instanceof Inet4Address) {
            result.setIdType(IDTypeEnum.IPV4_ADDR);
        } else {
            throw new UnsupportedOperationException("Not supported.");
        }
        result.setIdentificationData(addr.getAddress());
        secrets_v1.setIdentificationPayloadBody(result.getBody());
        if (ciphersuite_v1.getAuthMethod() == AuthAttributeEnum.PKE) {
            // this authentication method encrypts the identification using the public key of the peer
            PKCS1EncryptedISAKMPPayload pke = new PKCS1EncryptedISAKMPPayload(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyPKE());
            return pke;
        }
        if (ciphersuite_v1.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            // this authentication method encrypts the identification using a derived key
            result.setIdType(IDTypeEnum.KEY_ID);
            secrets_v1.setIdentificationPayloadBody(result.getBody());
            secrets_v1.computeSecretKeys();
            SymmetricallyEncryptedIdentificationPayloadHuaweiStyle rpke = new SymmetricallyEncryptedIdentificationPayloadHuaweiStyle(result, ciphersuite_v1, new SecretKeySpec(secrets_v1.getKe_i(), ciphersuite_v1.getCipher().cipherJCEName()), secrets_v1.getRPKEIV());
            rpke.encrypt();
            secrets_v1.setRPKEIV(rpke.getNextIV());
            return rpke;
        }
        return result;
    }

    public ISAKMPPayload prepareIKEv1NoncePayload(byte[] msgID) throws GeneralSecurityException {
        NoncePayload result = new NoncePayload();
        SecurityAssociationSecrets sas = this.secrets_v1.getSA(msgID);
        if (sas.getInitiatorNonce() == null) {
            SecureRandom random = new SecureRandom();
            byte[] initiatorNonce = new byte[ciphersuite_v1.getNonceLen()];
            random.nextBytes(initiatorNonce);
            sas.setInitiatorNonce(initiatorNonce);
        }
        result.setNonceData(sas.getInitiatorNonce());
        // these authentication methods encrypt the nonce using the public key of the peer
        if (Arrays.equals(msgID, new byte[4]) && ciphersuite_v1.getAuthMethod() == AuthAttributeEnum.PKE) {
            PKCS1EncryptedISAKMPPayload pke = new PKCS1EncryptedISAKMPPayload(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyPKE());
            return pke;
        }
        if (Arrays.equals(msgID, new byte[4]) && ciphersuite_v1.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            PKCS1EncryptedISAKMPPayload rpke = new PKCS1EncryptedISAKMPPayload(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyRPKE());
            return rpke;
        }
        return result;
    }

    public ISAKMPPayload preparePhase1HashPayload() throws GeneralSecurityException, IOException {
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(secrets_v1.getHASH_I());
        return hashPayload;
    }

    public ISAKMPPayload prepareIKEv1DeletePayload() throws GeneralSecurityException, IOException {
        DeletePayload deletePayload = new DeletePayload();
        byte[] concatCookies = new byte[ISAKMPMessage.COOKIE_LEN * 2];
        if (secrets_v1.getInitiatorCookie() != null) {
            System.arraycopy(secrets_v1.getInitiatorCookie(), 0, concatCookies, 0, ISAKMPMessage.COOKIE_LEN);
        }
        if (secrets_v1.getResponderCookie() != null) {
            System.arraycopy(secrets_v1.getResponderCookie(), 0, concatCookies, ISAKMPMessage.COOKIE_LEN, ISAKMPMessage.COOKIE_LEN);
        }
        deletePayload.addSPI(concatCookies);
        return deletePayload;
    }

    public void addIKEv1Phase2Hash1Payload(ISAKMPMessage msg) throws GeneralSecurityException, IOException {
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(secrets_v1.getHASH1(msg));
        msg.addPayload(0, hashPayload);
    }

    public void addIKEv1Phase2Hash3Payload(ISAKMPMessage msg) throws GeneralSecurityException, IOException {
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(secrets_v1.getHASH3(msg));
        msg.addPayload(0, hashPayload);
    }

    public void adjustCiphersuite(SecurityAssociationPayload sa) throws GeneralSecurityException, IKEHandshakeException {
        ciphersuite_v1.adjust(sa, secrets_v1);
    }

    public void adjustCiphersuite(SecurityAssociationPayloadv2 sa) throws GeneralSecurityException, IKEHandshakeException {
        ciphersuite_v2.adjust(sa, secrets_v2);
    }

    public IKEv2Payload prepareIKEv2KeyExchangePayload(byte[] msgID) throws GeneralSecurityException, IKEv2ParsingException {
        SecurityAssociationSecrets sas = this.secrets_v2.getSA(msgID);
        KeyExchangePayloadv2 result = new KeyExchangePayloadv2();
        result.setDhGroup(DHGroupTransformEnum.valueOf(sas.getDHGroup().name()));
        result.setKeyExchangeData(sas.generateKeyExchangeData());
        result.configureBody();
        return result;
    }

    public IKEv2Payload prepareIKEv2NoncePayload(byte[] msgID) throws GeneralSecurityException {
        NoncePayloadv2 result = new NoncePayloadv2();
        SecurityAssociationSecrets sas = this.secrets_v2.getSA(msgID);
        if (sas.getInitiatorNonce() == null) {
            SecureRandom random = new SecureRandom();
            byte[] initiatorNonce = new byte[ciphersuite_v2.getNonceLen()];
            random.nextBytes(initiatorNonce);
            sas.setInitiatorNonce(initiatorNonce);
        }
        result.setNonceData(sas.getInitiatorNonce());
        return result;
    }

    public IdentificationPayloadInitiator prepareIKEv2IdentificationInitiator() throws IOException, GeneralSecurityException {
        InetAddress addr = udpTH.getLocalAddress();
        IdentificationPayloadInitiator result = new IdentificationPayloadInitiator();
        result.setIdType(IDTypeEnum.IPV4_ADDR);
        result.setIdentificationData(addr.getAddress());
        result.setIDi();
        secrets_v2.setIDi(result.getIDi());
        secrets_v2.computeOctets();
        return result;
    }

    public AuthenticationPayload prepareIKEv2AuthenticationPayload() throws GeneralSecurityException {
        AuthenticationPayload result = new AuthenticationPayload();
        result.setAuthMethod(AuthMethodEnum.PSK);
        result.setAuthenticationData(secrets_v2.computeAUTH());
        return result;
    }

    public TrafficSelectorInitiatorPayload prepareIKEv2TrafficSelectorPayloadInitiator() {
        TrafficSelectorInitiatorPayload result = new TrafficSelectorInitiatorPayload();
        return result;
    }

    public TrafficSelectorPayloadResponder prepareIKEv2TrafficSelectorPayloadResponder() {
        TrafficSelectorPayloadResponder result = new TrafficSelectorPayloadResponder();
        return result;
    }

    public byte[] getNextv2MessageID() {
        return DatatypeHelper.intTo4ByteArray(nextv2MessageID);
    }
   
}
