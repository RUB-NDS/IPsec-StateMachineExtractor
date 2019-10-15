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
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
    List<ISAKMPMessage> messages;
    final long timeout;
    final InetAddress remoteAddress;
    final int remotePort;
    byte[] lastMsg;

    public IKEv1Handshake(long timeout, InetAddress remoteAddress, int remotePort) throws IOException, GeneralSecurityException {
        this.timeout = timeout;
        this.remoteAddress = remoteAddress;
        this.remotePort = remotePort;
        reset();
    }

    public ISAKMPMessage exchangeMessage(ISAKMPMessage messageToSend) throws IOException, ISAKMPParsingException, GeneralSecurityException, IKEHandshakeException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        if (messageToSend.isEncryptedFlag()) {
            messageToSend = EncryptedISAKMPMessage.fromPlainMessage(messageToSend, new SecretKeySpec(secrets.getKa(), ciphersuite.getCipher().cipherJCEName()), ciphersuite.getCipher(), secrets.getIV(messageToSend.getMessageId()));
        }
        if (secrets.getInitiatorCookie() == null) {
            secrets.setInitiatorCookie(messageToSend.getInitiatorCookie());
        } else {
            messageToSend.setInitiatorCookie(secrets.getInitiatorCookie());
        }
        messageToSend.setResponderCookie(secrets.getResponderCookie());
        if (messageToSend.getNextPayload() == PayloadTypeEnum.SecurityAssociation && secrets.getSAOfferBody() != null) {
            secrets.setSAOfferBody(messageToSend.getPayloads().get(0).getBody());
        }
        udpTH.sendData(messageToSend.getBytes());
        if (messageToSend.isEncryptedFlag()) {
            secrets.setIV(messageToSend.getMessageId(), ((EncryptedISAKMPMessage)messageToSend).getNextIV());
        }
        messages.add(messageToSend);
        byte[] rxData = udpTH.fetchData();
        if (rxData.length == 0) {
            return null;
        }
        if (Arrays.equals(rxData, lastMsg)) {
            return null; //only a retransmission
        }
        lastMsg = rxData;
        ISAKMPMessage messageReceived = ISAKMPMessageFromByteArray(rxData);
        messages.add(messageReceived);
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
            SecretKeySpec key = new SecretKeySpec(secrets.getKa(), ciphersuite.getCipher().cipherJCEName());
            byte[] iv = secrets.getIV(message.getMessageId());
            EncryptedISAKMPMessage encMessage = EncryptedISAKMPMessage.fromPlainMessage(message, key, ciphersuite.getCipher(), iv);
            encMessage.setCiphertext(bais);
            encMessage.setNextPayload(nextPayload);
            encMessage.decrypt();
            message = encMessage;
        } else {
            while (nextPayload != PayloadTypeEnum.NONE) {
                ISAKMPPayload payload;
                switch (nextPayload) {
                    case SecurityAssociation:
                        payload = SecurityAssociationPayload.fromStream(bais);
                        SecurityAssociationPayload receivedSAPayload = (SecurityAssociationPayload) payload;
                        adjustCiphersuite(receivedSAPayload);
                        break;
                    case KeyExchange:
                        payload = KeyExchangePayload.fromStream(bais);
                        secrets.setPeerKeyExchangeData(((KeyExchangePayload) payload).getKeyExchangeData());
                        secrets.computeDHSecret();
                        break;
                    case Identification:
                        switch (ciphersuite.getAuthMethod()) {
                            case PKE:
                                payload = ISAKMPPayloadWithPKCS1EncryptedBody.fromStream(IdentificationPayload.class, bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey()).getUnderlyingPayload();
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
                            throw new IKEHandshakeException("Responder Hashes do not match!");
                        }
                        break;
                    case Nonce:
                        switch (ciphersuite.getAuthMethod()) {
                            case PKE:
                            case RevPKE:
                                payload = ISAKMPPayloadWithPKCS1EncryptedBody.fromStream(NoncePayload.class, bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey()).getUnderlyingPayload();
                                break;
                            default:
                                payload = NoncePayload.fromStream(bais);
                                break;
                        }
                        secrets.setResponderNonce(((NoncePayload) payload).getNonceData());
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
        if (messageLength != message.getLength()) {
            throw new ISAKMPParsingException("Message lengths differ - Computed: " + message.getLength() + " vs. Received: " + messageLength + "!");
        }
        return message;
    }

    public void reset() throws IOException, GeneralSecurityException {
        ciphersuite = new IKEv1Ciphersuite();
        ltsecrets = new IKEv1HandshakeLongtermSecrets();
        secrets = new IKEv1HandshakeSessionSecrets(ciphersuite, ltsecrets);
        messages = new ArrayList<>();
        if (this.udpTH != null) {
            dispose();
        }
        this.udpTH = new LoquaciousClientUdpTransportHandler(this.timeout, this.remoteAddress.getHostAddress(), this.remotePort);
        prepareIdentificationPayload(); // sets secrets.identificationPayloadBody
        secrets.setPeerIdentificationPayloadBody(secrets.getIdentificationPayloadBody()); // only a default
        secrets.setSAOfferBody(SecurityAssociationPayloadFactory.PSK_DES_MD5_G1.getBody());
        secrets.generateDefaults();
    }

    public void adjustCiphersuite(SecurityAssociationPayload payload) throws GeneralSecurityException, IKEHandshakeException {
        if (payload.getProposalPayloads().size() != 1) {
            throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
        }
        ProposalPayload pp = payload.getProposalPayloads().get(0);
        if (pp.getTransformPayloads().size() != 1) {
            throw new IKEHandshakeException("Wrong number of transform payloads found. There should only be one.");
        }
        TransformPayload tp = pp.getTransformPayloads().get(0);
        tp.getAttributes().forEach((attr) -> {
            attr.configureCiphersuite(ciphersuite);
        });
    }

    public void dispose() throws IOException {
        if (udpTH.isInitialized()) {
            udpTH.closeConnection();
        }
    }

    public KeyExchangePayload prepareKeyExchangePayload() throws GeneralSecurityException {
        if (secrets.getInternalDHGroup() != ciphersuite.getDhGroup()) {
            secrets.generateDhKeyPair();
        }
        KeyExchangePayload result = new KeyExchangePayload();
        result.setKeyExchangeData(secrets.generateKeyExchangeData());
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

    public ISAKMPPayload prepareNoncePayload() throws GeneralSecurityException {
        NoncePayload result = new NoncePayload();
        if (secrets.getInitiatorNonce() == null) {
            SecureRandom random = new SecureRandom();
            byte[] initiatorNonce = new byte[ciphersuite.getNonceLen()];
            random.nextBytes(initiatorNonce);
            secrets.setInitiatorNonce(initiatorNonce);
        }
        result.setNonceData(secrets.getInitiatorNonce());
        if (ciphersuite.getAuthMethod() == AuthAttributeEnum.PKE || ciphersuite.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            // these authentication methods encrypt the nonce using the public key of the peer
            ISAKMPPayloadWithPKCS1EncryptedBody pke = new ISAKMPPayloadWithPKCS1EncryptedBody(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey());
            pke.encrypt();
            return pke;
        }
        return result;
    }

    public ISAKMPPayload prepareHashPayload() throws GeneralSecurityException, IOException {
        secrets.computeSecretKeys();
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(secrets.getHASH_I());
//        SymmetricallyEncryptedISAKMPSerializable encPayload = new SymmetricallyEncryptedISAKMPSerializable(hashPayload, secrets.getSKEYID_e(), ciphersuite.getCipher(), secrets.getIV());
//        encPayload.encrypt();
//        return encPayload;
        return hashPayload;
    }
}
