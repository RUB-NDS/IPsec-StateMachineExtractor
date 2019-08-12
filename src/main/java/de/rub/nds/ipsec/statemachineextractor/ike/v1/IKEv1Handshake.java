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
import de.rub.nds.ipsec.statemachineextractor.isakmp.EncryptedISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PKCS1EncryptedISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SymmetricallyEncryptedISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.TransformPayload;
import de.rub.nds.ipsec.statemachineextractor.util.LoquaciousClientUdpTransportHandler;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
        if (secrets.getInitiatorCookie() == null) {
            secrets.setInitiatorCookie(messageToSend.getInitiatorCookie());
        } else {
            messageToSend.setInitiatorCookie(secrets.getInitiatorCookie());
        }
        messageToSend.setResponderCookie(secrets.getResponderCookie());
        if (messageToSend.getNextPayload() == PayloadTypeEnum.SecurityAssociation) {
            secrets.setSAOfferBody(messageToSend.getPayloads().get(0).getBody());
        }
        udpTH.sendData(messageToSend.getBytes());
        messages.add(messageToSend);
        byte[] rxData = udpTH.fetchData();
        if (rxData.length == 0) {
            return null;
        }
        if (Arrays.equals(rxData, lastMsg)) {
            return null; //only a retransmission
        }
        lastMsg = rxData;
        ISAKMPMessage messageReceived = IKEv1MessageBuilder.fromByteArray(rxData, ciphersuite, ltsecrets);
        messages.add(messageReceived);
        extractProperties(messageReceived);
        return messageReceived;
    }

    void extractProperties(ISAKMPMessage msg) throws GeneralSecurityException, IKEHandshakeException {
        secrets.setResponderCookie(msg.getResponderCookie());
        for (ISAKMPPayload payload : msg.getPayloads()) {
            switch (payload.getType()) {
                case SecurityAssociation:
                    SecurityAssociationPayload receivedSAPayload = (SecurityAssociationPayload) payload;
                    adjustCiphersuite(receivedSAPayload);
                    break;
                case KeyExchange:
                    secrets.setPeerKeyExchangeData(((KeyExchangePayload) payload).getKeyExchangeData());
                    secrets.computeDHSecret();
                    break;
                case Identification:
                    if (payload instanceof EncryptedISAKMPPayload) {
                        EncryptedISAKMPPayload encPayload = (EncryptedISAKMPPayload) payload;
                        payload = encPayload.getPlainPayload();
                    }
                    secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) payload).getBody());
                    secrets.computeSecretKeys();
                    break;
                case Nonce:
                    if (payload instanceof EncryptedISAKMPPayload) {
                        EncryptedISAKMPPayload encPayload = (EncryptedISAKMPPayload) payload;
                        payload = encPayload.getPlainPayload();
                    }
                    secrets.setResponderNonce(((NoncePayload) payload).getNonceData());
                    secrets.computeSecretKeys();
                    break;
                case VendorID:
                    break;
                default:
                    throw new UnsupportedOperationException("Not supported yet: " + payload.getType().toString());
            }
        }
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
        secrets.generateDhKeyPair();
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
            PKCS1EncryptedISAKMPPayload pke = new PKCS1EncryptedISAKMPPayload(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey());
            pke.encrypt();
            return pke;
        }
        if (ciphersuite.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            // this authentication method encrypts the identification using a derived key
            throw new UnsupportedOperationException("Not supported yet.");
        }
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
            PKCS1EncryptedISAKMPPayload pke = new PKCS1EncryptedISAKMPPayload(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey());
            pke.encrypt();
            return pke;
        }
        return result;
    }

    public ISAKMPPayload prepareHashPayload() throws GeneralSecurityException, IOException {
        secrets.computeSecretKeys();
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(secrets.getHASH_I());
        SymmetricallyEncryptedISAKMPPayload encPayload = new SymmetricallyEncryptedISAKMPPayload(hashPayload, secrets.getSKEYID_e(), ciphersuite.getCipher(), secrets.getIV());
        encPayload.encrypt();
        return encPayload;
    }
}
