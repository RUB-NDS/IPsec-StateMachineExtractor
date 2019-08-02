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
import de.rub.nds.ipsec.statemachineextractor.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.TransformPayload;
import de.rub.nds.ipsec.statemachineextractor.util.LoquaciousClientUdpTransportHandler;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Mac;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IKEv1Handshake {

    LoquaciousClientUdpTransportHandler udpTH;
    IKEv1Ciphersuite ciphersuite = new IKEv1Ciphersuite();
    IKEv1HandshakeSecrets secrets = new IKEv1HandshakeSecrets(ciphersuite);
    List<ISAKMPMessage> messages = new ArrayList<>();
    SecurityAssociationPayload lastReceivedSAPayload;

    public IKEv1Handshake(long timeout, InetAddress remoteAddress, int port) throws IOException, GeneralSecurityException {
        this.udpTH = new LoquaciousClientUdpTransportHandler(timeout, remoteAddress.getHostAddress(), port);
        prepareIdentificationPayload(); // sets secrets.identificationPayloadBody
        secrets.setPeerIdentificationPayloadBody(secrets.getIdentificationPayloadBody()); // only a default
        secrets.generateDefaults();
        lastReceivedSAPayload = SecurityAssociationPayloadFactory.PSK_DES_MD5_G1;
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
        udpTH.sendData(messageToSend.getBytes());
        messages.add(messageToSend);
        byte[] rxData = udpTH.fetchData();
        if (rxData.length == 0) {
            throw new IOException("No data received within timeout");
        }
        ISAKMPMessage messageReceived = IKEv1MessageBuilder.fromByteArray(rxData);
        messages.add(messageReceived);
        extractProperties(messageReceived);
        return messageReceived;
    }

    void extractProperties(ISAKMPMessage msg) throws GeneralSecurityException, IKEHandshakeException {
        secrets.setResponderCookie(msg.getResponderCookie());
        for (ISAKMPPayload payload : msg.getPayloads()) {
            switch (payload.getType()) {
                case SecurityAssociation:
                    lastReceivedSAPayload = (SecurityAssociationPayload) payload;
                    if (lastReceivedSAPayload.getProposalPayloads().size() != 1) {
                        throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
                    }
                    ProposalPayload pp = lastReceivedSAPayload.getProposalPayloads().get(0);
                    if (pp.getTransformPayloads().size() != 1) {
                        throw new IKEHandshakeException("Wrong number of transform payloads found. There should only be one.");
                    }
                    TransformPayload tp = pp.getTransformPayloads().get(0);
                    tp.getAttributes().forEach((attr) -> {
                        attr.configureCiphersuite(ciphersuite);
                    });
                    break;
                case KeyExchange:
                    secrets.setPeerKeyExchangeData(((KeyExchangePayload) payload).getKeyExchangeData());
                    secrets.computeDHSecret();
                    break;
                case Identification:
                    secrets.setIdentificationPayloadBody(((IdentificationPayload) payload).getBody());
                    break;
                case Nonce:
                    secrets.setResponderNonce(((NoncePayload) payload).getNonceData());
                    break;
                default:
                    throw new UnsupportedOperationException("Not supported yet: " + payload.getType().toString());
            }
        }
    }

    public void dispose() throws IOException {
        if (udpTH.isInitialized()) {
            udpTH.closeConnection();
        }
    }

    public KeyExchangePayload prepareKeyExchangePayload() throws GeneralSecurityException {
        KeyExchangePayload result = new KeyExchangePayload();
        result.setKeyExchangeData(secrets.generateKeyExchangeData());
        return result;
    }

    public IdentificationPayload prepareIdentificationPayload() throws IOException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        InetAddress addr = udpTH.getLocalAddress();
        IdentificationPayload result = new IdentificationPayload();
        if (addr instanceof Inet6Address) {
            result.setIdType(IDTypeEnum.ID_IPV6_ADDR);
            result.setIdentificationData(addr.getAddress());
        } else if (addr instanceof Inet4Address) {
            result.setIdType(IDTypeEnum.ID_IPV4_ADDR);
            result.setIdentificationData(addr.getAddress());
        }
        secrets.setIdentificationPayloadBody(result.getBody());
        return result;
    }

    public NoncePayload prepareNoncePayload() {
        NoncePayload result = new NoncePayload();
        if (secrets.getInitiatorNonce() == null) {
            SecureRandom random = new SecureRandom();
            byte[] initiatorNonce = new byte[ciphersuite.getNonceLen()];
            random.nextBytes(initiatorNonce);
            secrets.setInitiatorNonce(initiatorNonce);
        }
        result.setNonceData(secrets.getInitiatorNonce());
        return result;
    }

    public HashPayload prepareHashPayload() throws GeneralSecurityException, IOException {
        if (secrets.getSKEYID() == null) {
            secrets.computeSKEYID();
        }
        Mac prf = Mac.getInstance("Hmac" + ciphersuite.getHash().toString());
        prf.init(secrets.getSKEYID());
        prf.update(secrets.getKeyExchangeData());
        prf.update(secrets.getPeerKeyExchangeData());
        prf.update(secrets.getInitiatorCookie());
        prf.update(secrets.getResponderCookie());
        prf.update(lastReceivedSAPayload.getBody());
        byte[] initiatorHash = prf.doFinal(secrets.getIdentificationPayloadBody());
        HashPayload result = new HashPayload();
        result.setHashData(initiatorHash);
        return result;
    }
}
