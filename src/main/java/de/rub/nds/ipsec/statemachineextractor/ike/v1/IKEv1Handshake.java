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
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.IKEv1Attribute;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.EncryptedISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayloadWithPKCS1EncryptedBody;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NotificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.TransformPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.VendorIDPayload;
import de.rub.nds.ipsec.statemachineextractor.util.LoquaciousClientUdpTransportHandler;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
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
public final class IKEv1Handshake {

    LoquaciousClientUdpTransportHandler udpTH;
    IKEv1Ciphersuite ciphersuite;
    IKEv1HandshakeLongtermSecrets ltsecrets;
    IKEv1HandshakeSessionSecrets secrets;
    List<WireMessage> messages = new ArrayList<>();
    final long timeout;
    final InetAddress remoteAddress;
    final int remotePort;

    public IKEv1Handshake(long timeout, InetAddress remoteAddress, int remotePort) throws IOException, GeneralSecurityException {
        this.timeout = timeout;
        this.remoteAddress = remoteAddress;
        this.remotePort = remotePort;
        reset();
    }

    public ISAKMPMessage retransmit() throws IOException, ISAKMPParsingException, GeneralSecurityException, IKEHandshakeException {
        if (messages.isEmpty()) {
            return null;
        }
        List<WireMessage> txMsgs = messages.stream().filter(wm -> wm.isSentByMe == true).collect(Collectors.toList());
        WireMessage lastTXMsg = txMsgs.get(txMsgs.size() - 1);
        byte[] txData = lastTXMsg.getData().array();
        byte[] rxData = exchangeData(txData);
        if (rxData == null) {
            return null;
        }
        //received an answer that is no retransmission, so store messages and last ciphertext block as IV
        messages.add(lastTXMsg);
        if (lastTXMsg.getMessage().isEncryptedFlag()) {
            secrets.setIV(lastTXMsg.getMessage().getMessageId(), ((EncryptedISAKMPMessage) lastTXMsg.getMessage()).getNextIV());
        }
        ISAKMPMessage messageReceived = ISAKMPMessageFromByteArray(rxData);
        messages.add(new WireMessage(rxData, messageReceived, false));
        return messageReceived;
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
        Set<ByteBuffer> rxMsgs = messages.stream().filter(wm -> wm.isSentByMe == false).map(WireMessage::getData).collect(Collectors.toSet());
        if (rxMsgs.contains(ByteBuffer.wrap(rxData))) {
            return null; //only a retransmission
        }
        return rxData;
    }

    public ISAKMPMessage exchangeMessage(ISAKMPMessage messageToSend) throws IOException, ISAKMPParsingException, GeneralSecurityException, IKEHandshakeException {
        if (messageToSend.isEncryptedFlag()) {
            messageToSend = EncryptedISAKMPMessage.fromPlainMessage(messageToSend, new SecretKeySpec(secrets.getKa(), ciphersuite.getCipher().cipherJCEName()), ciphersuite.getCipher(), secrets.getIV(messageToSend.getMessageId()));
        }
        if (secrets.getInitiatorCookie() == null) {
            secrets.setInitiatorCookie(messageToSend.getInitiatorCookie());
        } else {
            messageToSend.setInitiatorCookie(secrets.getInitiatorCookie());
        }
        messageToSend.setResponderCookie(secrets.getResponderCookie());
        if (messageToSend.getNextPayload() == PayloadTypeEnum.SecurityAssociation && secrets.getISAKMPSA().getSAOfferBody() == null) {
            secrets.getISAKMPSA().setSAOfferBody(messageToSend.getPayloads().get(0).getBody());
        }
        byte[] txData = messageToSend.getBytes();
        messages.add(new WireMessage(txData, messageToSend, true));
        byte[] rxData = exchangeData(txData);
        if (rxData == null) {
            return null;
        }
        if (messageToSend.isEncryptedFlag()) {
            //received an answer, so store last ciphertext block as IV for decryption
            secrets.setIV(messageToSend.getMessageId(), ((EncryptedISAKMPMessage) messageToSend).getNextIV());
        }
        ISAKMPMessage messageReceived = ISAKMPMessageFromByteArray(rxData);
        if (messageToSend.isEncryptedFlag()) {
            //message could be unmarshalled, so store last ciphertext block as IV for next encryption
            secrets.setIV(messageReceived.getMessageId(), Arrays.copyOfRange(rxData, rxData.length - ciphersuite.getCipher().getBlockSize(), rxData.length));
        }
        messages.add(new WireMessage(rxData, messageReceived, false));
        return messageReceived;
    }

    ISAKMPMessage ISAKMPMessageFromByteArray(byte[] bytes) throws ISAKMPParsingException, GeneralSecurityException, IKEHandshakeException {
        if (bytes.length < ISAKMPMessage.ISAKMP_HEADER_LEN) {
            throw new ISAKMPParsingException("Not enough bytes supplied to build an ISAKMPMessage!");
        }
        switch (ExchangeTypeEnum.get(bytes[18])) {
            case Aggressive:
            case IdentityProtection:
            case Informational:
            case QuickMode:
                break;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
        ISAKMPMessage message = new ISAKMPMessage();
        message.setInitiatorCookie(Arrays.copyOfRange(bytes, 0, 8));
        message.setResponderCookie(Arrays.copyOfRange(bytes, 8, 16));
        message.setVersion(bytes[17]);
        message.setExchangeType(ExchangeTypeEnum.get(bytes[18]));
        message.setEncryptedFlag((bytes[19] & 1) > 0);
        message.setCommitFlag((bytes[19] & 2) > 0);
        message.setAuthenticationOnlyFlag((bytes[19] & 4) > 0);
        message.setMessageId(Arrays.copyOfRange(bytes, 20, 24));
        int messageLength = new BigInteger(Arrays.copyOfRange(bytes, 24, 28)).intValue();
        secrets.setResponderCookie(message.getResponderCookie());

        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        bais.skip(ISAKMPMessage.ISAKMP_HEADER_LEN);
        PayloadTypeEnum nextPayload = PayloadTypeEnum.get(bytes[16]);
        if (message.isEncryptedFlag()) {
            message = processEncryptedMessage(message, nextPayload, bais);
        } else {
            processPlainMessage(message, nextPayload, bais);
        }
        if (messageLength != message.getLength()) {
            throw new ISAKMPParsingException("Message lengths differ - Computed: " + message.getLength() + " vs. Received: " + messageLength + "!");
        }
        return message;
    }

    private ISAKMPMessage processEncryptedMessage(ISAKMPMessage encMessage, PayloadTypeEnum nextPayload, ByteArrayInputStream bais) throws GeneralSecurityException, ISAKMPParsingException, IKEHandshakeException {
        SecretKeySpec key = new SecretKeySpec(secrets.getKa(), ciphersuite.getCipher().cipherJCEName());
        byte[] iv = secrets.getIV(encMessage.getMessageId());
        EncryptedISAKMPMessage decMessage = EncryptedISAKMPMessage.fromPlainMessage(encMessage, key, ciphersuite.getCipher(), iv);
        decMessage.setCiphertext(bais);
        decMessage.setNextPayload(nextPayload);
        decMessage.decrypt();
        PayloadTypeEnum payloadType = nextPayload;
        for (ISAKMPPayload payload : decMessage.getPayloads()) {
            switch (payloadType) {
                case Hash:
                    byte[] expectedHash = null;
                    switch (decMessage.getExchangeType()) {
                        case IdentityProtection:
                            expectedHash = secrets.getHASH_R();
                            break;
                        case Informational:
                            expectedHash = secrets.getHASH1(decMessage);
                            break;
                        case QuickMode:
                            expectedHash = secrets.getHASH2(decMessage);
                            break;
                    }
                    if (!Arrays.equals(expectedHash, ((HashPayload) payload).getHashData())) {
                        ((HashPayload) payload).setIsCheckFailed(true);
                    }
                    break;
                case Nonce:
                    secrets.getSA(decMessage.getMessageId()).setResponderNonce(((NoncePayload) payload).getNonceData());
                    break;
            }
            payloadType = payload.getNextPayload();
        }
        return decMessage;
    }

    private void processPlainMessage(ISAKMPMessage message, PayloadTypeEnum nextPayload, ByteArrayInputStream bais) throws ISAKMPParsingException, GeneralSecurityException, IllegalStateException, UnsupportedOperationException, IKEHandshakeException {
        ISAKMPPayload payload;
        while (nextPayload != PayloadTypeEnum.NONE) {
            switch (nextPayload) {
                case SecurityAssociation:
                    payload = SecurityAssociationPayload.fromStream(bais);
                    SecurityAssociationPayload receivedSAPayload = (SecurityAssociationPayload) payload;
                    adjustCiphersuite(receivedSAPayload);
                    break;
                case KeyExchange:
                    payload = KeyExchangePayload.fromStream(bais);
                    secrets.getISAKMPSA().setPeerKeyExchangeData(((KeyExchangePayload) payload).getKeyExchangeData());
                    secrets.getISAKMPSA().computeDHSecret();
                    break;
                case Identification:
                    switch (ciphersuite.getAuthMethod()) {
                        case PKE:
                            payload = ISAKMPPayloadWithPKCS1EncryptedBody.fromStream(IdentificationPayload.class,
                                    bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey()).getUnderlyingPayload();
                            break;
                        case RevPKE:
                            throw new UnsupportedOperationException("Not supported yet.");
                        //break;
                        default:
                            payload = IdentificationPayload.fromStream(bais);
                            break;
                    }
                    secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) payload).getBody());
                    secrets.computeSecretKeys();
                    break;
                case Hash:
                    payload = HashPayload.fromStream(bais);
                    if (!Arrays.equals(secrets.getHASH_R(), ((HashPayload) payload).getHashData())) {
                        throw new IKEHandshakeException("Aggressive Mode HASH_R does not match!");
                    }
                    break;
                case Nonce:
                    switch (ciphersuite.getAuthMethod()) {
                        case PKE:
                        case RevPKE:
                            payload = ISAKMPPayloadWithPKCS1EncryptedBody.fromStream(NoncePayload.class,
                                    bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey()).getUnderlyingPayload();
                            break;
                        default:
                            payload = NoncePayload.fromStream(bais);
                            break;
                    }
                    secrets.getISAKMPSA().setResponderNonce(((NoncePayload) payload).getNonceData());
                    secrets.computeSecretKeys();
                    break;
                case VendorID:
                    payload = VendorIDPayload.fromStream(bais);
                    break;
                case Notification:
                    payload = NotificationPayload.fromStream(bais);
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
        ciphersuite = new IKEv1Ciphersuite();
        ltsecrets = new IKEv1HandshakeLongtermSecrets();
        secrets = new IKEv1HandshakeSessionSecrets(ciphersuite, ltsecrets);
        if (this.udpTH != null) {
            dispose();
        }
        this.udpTH = new LoquaciousClientUdpTransportHandler(this.timeout, this.remoteAddress.getHostAddress(), this.remotePort);
        prepareIdentificationPayload(); // sets secrets.identificationPayloadBody
        secrets.setPeerIdentificationPayloadBody(secrets.getIdentificationPayloadBody()); // only a default
        secrets.getISAKMPSA().setSAOfferBody(SecurityAssociationPayloadFactory.P1_PSK_DES_MD5_G1.getBody());
        secrets.generateDefaults();
    }

    public void adjustCiphersuite(SecurityAssociationPayload payload) throws GeneralSecurityException, IKEHandshakeException {
        if (payload.getProposalPayloads().size() != 1) {
            throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
        }
        ProposalPayload pp = payload.getProposalPayloads().get(0);
        if (pp.getProtocolId() != ProtocolIDEnum.ISAKMP) {
            throw new IKEHandshakeException("Proposal protocol is not ISAKMP.");
        }
        if (pp.getTransformPayloads().size() != 1) {
            throw new IKEHandshakeException("Wrong number of transform payloads found. There should only be one.");
        }
        TransformPayload tp = pp.getTransformPayloads().get(0);
        if (tp.getTransformId().getValue() != ProtocolTransformIDEnum.ISAKMP_KEY_IKE.getValue()) {
            throw new IKEHandshakeException("Transform ID is not the the hybrid ISAKMP/Oakley Diffie-Hellman key exchange (IKE).");
        }
        tp.getAttributes().forEach((attr) -> {
            IKEv1Attribute iattr = (IKEv1Attribute) attr;
            iattr.configureCiphersuite(ciphersuite);
        });
        secrets.updateISAKMPSA();
    }

    public void dispose() throws IOException {
        if (udpTH.isInitialized()) {
            udpTH.closeConnection();
        }
    }

    public byte[] getMostRecentMessageID() {
        return secrets.getMostRecentMessageID();
    }

    public void setMostRecentMessageID(byte[] mostRecentMessageID) {
        secrets.setMostRecentMessageID(mostRecentMessageID);
    }

    public KeyExchangePayload prepareKeyExchangePayload(byte[] msgID) throws GeneralSecurityException {
        KeyExchangePayload result = new KeyExchangePayload();
        SASecrets sas = this.secrets.getSA(msgID);
        result.setKeyExchangeData(sas.generateKeyExchangeData());
        return result;
    }

    public ISAKMPPayload prepareIdentificationPayload() throws IOException, GeneralSecurityException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        InetAddress addr = udpTH.getLocalAddress();
        IdentificationPayload result = new IdentificationPayload();
        if (addr instanceof Inet6Address) {
            result.setIdType(IDTypeEnum.ID_IPV6_ADDR);
        } else if (addr instanceof Inet4Address) {
            result.setIdType(IDTypeEnum.ID_IPV4_ADDR);
        }
        result.setIdentificationData(addr.getAddress());
        if (ciphersuite.getAuthMethod() == AuthAttributeEnum.PKE) {
            // this authentication method encrypts the identification using the public key of the peer
            ISAKMPPayloadWithPKCS1EncryptedBody pke = new ISAKMPPayloadWithPKCS1EncryptedBody(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey());
            pke.encrypt();
            return pke;
        }
        if (ciphersuite.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            // this authentication method encrypts the identification using a derived key
            throw new UnsupportedOperationException("Not supported yet.");
        }
        secrets.setIdentificationPayloadBody(result.getBody());
        return result;
    }

    public ISAKMPPayload prepareNoncePayload(byte[] msgID) throws GeneralSecurityException {
        NoncePayload result = new NoncePayload();
        SASecrets sas = this.secrets.getSA(msgID);
        if (sas.getInitiatorNonce() == null) {
            SecureRandom random = new SecureRandom();
            byte[] initiatorNonce = new byte[ciphersuite.getNonceLen()];
            random.nextBytes(initiatorNonce);
            sas.setInitiatorNonce(initiatorNonce);
        }
        result.setNonceData(sas.getInitiatorNonce());
        if (ciphersuite.getAuthMethod() == AuthAttributeEnum.PKE || ciphersuite.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            // these authentication methods encrypt the nonce using the public key of the peer
            ISAKMPPayloadWithPKCS1EncryptedBody pke = new ISAKMPPayloadWithPKCS1EncryptedBody(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey());
            pke.encrypt();
            return pke;
        }
        return result;
    }

    public ISAKMPPayload preparePhase1HashPayload() throws GeneralSecurityException, IOException {
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(secrets.getHASH_I());
        return hashPayload;
    }

    public void addPhase2Hash1Payload(ISAKMPMessage msg) throws GeneralSecurityException, IOException {
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(secrets.getHASH1(msg));
        msg.addPayload(0, hashPayload);
    }

    public void addPhase2Hash3Payload(ISAKMPMessage msg) throws GeneralSecurityException, IOException {
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(secrets.getHASH3(msg));
        msg.addPayload(0, hashPayload);
    }
}
