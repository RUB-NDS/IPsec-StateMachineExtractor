/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.HandshakeLongtermSecrets;
import de.rub.nds.ipsec.statemachineextractor.WireMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.DeletePayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.EncryptedISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.ExchangeTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.PKCS1EncryptedISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.NotificationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SymmetricallyEncryptedISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.SymmetricallyEncryptedIdentificationPayloadHuaweiStyle;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.TransformPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.VendorIDPayload;
import de.rub.nds.ipsec.statemachineextractor.networking.LoquaciousClientUdpTransportHandler;
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
import javax.crypto.BadPaddingException;
import javax.crypto.spec.SecretKeySpec;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPAttribute;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IKEv1Handshake {

    LoquaciousClientUdpTransportHandler udpTH;
    IKEv1Ciphersuite ciphersuite;
    HandshakeLongtermSecrets ltsecrets;
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

    public ISAKMPMessage exchangeMessage(ISAKMPMessage messageToSend) throws IOException, GenericIKEParsingException, GeneralSecurityException, IKEHandshakeException {
        if (messageToSend.isEncryptedFlag()) {
            messageToSend = EncryptedISAKMPMessage.fromPlainMessage(messageToSend, new SecretKeySpec(secrets.getKa(), ciphersuite.getCipher().cipherJCEName()), ciphersuite.getCipher(), secrets.getIV(messageToSend.getMessageId()));
        }
        if (secrets.getInitiatorCookie() == null) {
            secrets.setInitiatorCookie(messageToSend.getInitiatorCookie());
        } else {
            messageToSend.setInitiatorCookie(secrets.getInitiatorCookie());
        }
        messageToSend.setResponderCookie(secrets.getResponderCookie());
        if (messageToSend.getNextPayload() == IKEPayloadTypeEnum.SecurityAssociation && secrets.getHandshakeSA().getSAOfferBody() == null) {
            secrets.getHandshakeSA().setSAOfferBody(messageToSend.getPayloads().get(0).getBody());
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

    ISAKMPMessage ISAKMPMessageFromByteArray(byte[] bytes) throws GenericIKEParsingException, GeneralSecurityException, IKEHandshakeException {
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
        if (messageLength < bytes.length) {
            //received more data than the message's length field said.
            //this happens when the responder e.g. sends a Notification during the handshake (e.g. ResponderLifetime)
            //for now, we just ignore this additional message
            //TODO: Parse more than one message
            bytes = Arrays.copyOf(bytes, messageLength);
        }
        secrets.setResponderCookie(message.getResponderCookie());

        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        bais.skip(ISAKMPMessage.ISAKMP_HEADER_LEN);
        IKEPayloadTypeEnum nextPayload = IKEPayloadTypeEnum.get(bytes[16]);
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

    private ISAKMPMessage processEncryptedMessage(ISAKMPMessage encMessage, IKEPayloadTypeEnum nextPayload, ByteArrayInputStream bais) throws GeneralSecurityException, ISAKMPParsingException, IKEHandshakeException {
        SecretKeySpec key = new SecretKeySpec(secrets.getKa(), ciphersuite.getCipher().cipherJCEName());
        byte[] iv = secrets.getIV(encMessage.getMessageId());
        EncryptedISAKMPMessage decMessage = EncryptedISAKMPMessage.fromPlainMessage(encMessage, key, ciphersuite.getCipher(), iv);
        decMessage.setCiphertext(bais);
        decMessage.setNextPayload(nextPayload);
        decMessage.decrypt();
        IKEPayloadTypeEnum payloadType = nextPayload;
        for (ISAKMPPayload payload : decMessage.getPayloads()) {
            switch (payloadType) {
                case SecurityAssociation:
                    SecurityAssociationPayload sa = (SecurityAssociationPayload) payload;
                    if (sa.getProposalPayloads().size() != 1) {
                        throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
                    }
                    ProposalPayload pp = sa.getProposalPayloads().get(0);
                    SecurityAssociationSecrets sas = this.getMostRecentSecurityAssociation();
                    sas.setOutboundSpi(pp.getSPI());
                    break;
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
                    if (Arrays.equals(expectedHash, ((HashPayload) payload).getHashData())) {
                        ((HashPayload) payload).setCheckFailed(false);
                    } else {
                        ((HashPayload) payload).setCheckFailed(true);
                    }
                    break;
                case Nonce:
                    secrets.getSA(decMessage.getMessageId()).setResponderNonce(((NoncePayload) payload).getNonceData());
                    break;
                case Identification:
                    if (decMessage.getExchangeType() != ExchangeTypeEnum.QuickMode) {
                        switch (ciphersuite.getAuthMethod()) {
                            case PSK:
                                secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) payload).getBody());
                                secrets.computeSecretKeys();
                                break;
                            case DSS_Sig:
                            case RSA_Sig:
                                throw new UnsupportedOperationException("Not supported yet.");
                            default:
                                throw new UnsupportedOperationException("This authentication should not be sending encrypted identification payloads.");
                        }
                        secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) payload).getBody());
                        secrets.computeSecretKeys();
                    }
                    break;
            }
            payloadType = payload.getNextPayload();
        }
        return decMessage;
    }

    private void processPlainMessage(ISAKMPMessage message, IKEPayloadTypeEnum nextPayload, ByteArrayInputStream bais) throws GenericIKEParsingException, GeneralSecurityException, IllegalStateException, UnsupportedOperationException, IKEHandshakeException {
        ISAKMPPayload payload;
        while (nextPayload != IKEPayloadTypeEnum.NONE) {
            switch (nextPayload) {
                case SecurityAssociation:
                    payload = SecurityAssociationPayload.fromStream(bais);
                    SecurityAssociationPayload receivedSAPayload = (SecurityAssociationPayload) payload;
                    adjustCiphersuite(receivedSAPayload);
                    break;
                case KeyExchange:
                    switch (ciphersuite.getAuthMethod()) {
                        case RevPKE:
                            SecretKeySpec ke_r = new SecretKeySpec(secrets.getKe_r(), ciphersuite.getCipher().cipherJCEName());
                            SymmetricallyEncryptedISAKMPPayload symmPayload = SymmetricallyEncryptedISAKMPPayload.fromStream(KeyExchangePayload.class, bais, ciphersuite, ke_r, secrets.getRPKEIV());
                            secrets.getHandshakeSA().setPeerKeyExchangeData(((KeyExchangePayload) symmPayload.getUnderlyingPayload()).getKeyExchangeData());
                            payload = symmPayload;
                            break;
                        default:
                            payload = KeyExchangePayload.fromStream(bais);
                            secrets.getHandshakeSA().setPeerKeyExchangeData(((KeyExchangePayload) payload).getKeyExchangeData());
                            break;
                    }
                    secrets.getHandshakeSA().computeDHSecret();
                    break;
                case Identification:
                    bais.mark(0);
                    switch (ciphersuite.getAuthMethod()) {
                        case RevPKE:
                            SecretKeySpec ke_r = new SecretKeySpec(secrets.getKe_r(), ciphersuite.getCipher().cipherJCEName());
                            SymmetricallyEncryptedIdentificationPayloadHuaweiStyle symmPayload = SymmetricallyEncryptedIdentificationPayloadHuaweiStyle.fromStream(bais, ciphersuite, ke_r, secrets.getRPKEIV());
                            secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) symmPayload.getUnderlyingPayload()).getBody());
                            payload = symmPayload;
                            break;
                        case PKE:
                            try {
                                PKCS1EncryptedISAKMPPayload pkcs1Payload = PKCS1EncryptedISAKMPPayload.fromStream(IdentificationPayload.class, bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyPKE());
                                secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) pkcs1Payload.getUnderlyingPayload()).getBody());
                                payload = pkcs1Payload;
                                break; // only executed when there's no exception
                            } catch (ISAKMPParsingException ex) {
                                if (!(ex.getCause() instanceof BadPaddingException)) {
                                    throw ex;
                                }
                                // Payload was probably not encrypted, let's use the default case
                                bais.reset();
                            }
                        default:
                            payload = IdentificationPayload.fromStream(bais);
                            secrets.setPeerIdentificationPayloadBody(((IdentificationPayload) payload).getBody());
                            break;
                    }
                    secrets.computeSecretKeys();
                    break;
                case Hash:
                    payload = HashPayload.fromStream(bais);
                    if (Arrays.equals(secrets.getHASH_R(), ((HashPayload) payload).getHashData())) {
                        ((HashPayload) payload).setCheckFailed(false);
                    } else {
                        ((HashPayload) payload).setCheckFailed(true);
                    }
                    break;
                case Nonce:
                    switch (ciphersuite.getAuthMethod()) {
                        case PKE:
                        case RevPKE:
                            bais.mark(0);
                            try {
                                PKCS1EncryptedISAKMPPayload encPayload = PKCS1EncryptedISAKMPPayload.fromStream(NoncePayload.class, bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyRPKE());
                                secrets.getHandshakeSA().setResponderNonce(((NoncePayload) encPayload.getUnderlyingPayload()).getNonceData());
                                payload = encPayload;
                                break; // only executed when there's no exception
                            } catch (ISAKMPParsingException ex) {
                                if (!(ex.getCause() instanceof BadPaddingException)) {
                                    throw ex;
                                }
                                // Payload was probably not encrypted, let's use the default case
                                bais.reset();
                            }
                        default:
                            payload = NoncePayload.fromStream(bais);
                            secrets.getHandshakeSA().setResponderNonce(((NoncePayload) payload).getNonceData());
                            break;
                    }
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
        ltsecrets = new HandshakeLongtermSecrets();
        secrets = new IKEv1HandshakeSessionSecrets(ciphersuite, ltsecrets);
        if (this.udpTH != null) {
            dispose();
        }
        this.udpTH = new LoquaciousClientUdpTransportHandler(this.timeout, this.remoteAddress.getHostAddress(), this.remotePort);
        prepareIdentificationPayload(); // sets secrets.identificationPayloadBody
        secrets.setPeerIdentificationPayloadBody(secrets.getIdentificationPayloadBody()); // only a default
        secrets.getHandshakeSA().setSAOfferBody(null);
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
            ISAKMPAttribute iattr = (ISAKMPAttribute) attr;
            iattr.configureCiphersuite(ciphersuite);
        });
        secrets.updateHandshakeSA();
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

    public SecurityAssociationSecrets getMostRecentSecurityAssociation() {
        return secrets.getSA(secrets.getMostRecentMessageID());
    }

    public void computeIPsecKeyMaterial(SecurityAssociationSecrets sas) throws GeneralSecurityException {
        secrets.computeKeyMaterial(sas);
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

    public ISAKMPPayload prepareKeyExchangePayload(byte[] msgID) throws GeneralSecurityException {
        KeyExchangePayload result = new KeyExchangePayload();
        SecurityAssociationSecrets sas = this.secrets.getSA(msgID);
        result.setKeyExchangeData(sas.generateKeyExchangeData());
        if (ciphersuite.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            // this authentication method encrypts the key exchange value using a derived key
            secrets.computeSecretKeys();
            SymmetricallyEncryptedISAKMPPayload rpke = new SymmetricallyEncryptedISAKMPPayload(result, ciphersuite, new SecretKeySpec(secrets.getKe_i(), ciphersuite.getCipher().cipherJCEName()), secrets.getRPKEIV());
            rpke.encrypt();
            secrets.setRPKEIV(rpke.getNextIV());
            return rpke;
        }
        return result;
    }

    public ISAKMPPayload prepareIdentificationPayload() throws IOException, GeneralSecurityException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        InetAddress addr = udpTH.getLocalAddress();
        IdentificationPayload result = new IdentificationPayload();
        if (addr instanceof Inet6Address) {
            result.setIdType(IDTypeEnum.IPV6_ADDR);
        } else if (addr instanceof Inet4Address) {
            result.setIdType(IDTypeEnum.IPV4_ADDR);
        }
        result.setIdentificationData(addr.getAddress());
        secrets.setIdentificationPayloadBody(result.getBody());
        if (ciphersuite.getAuthMethod() == AuthAttributeEnum.PKE) {
            // this authentication method encrypts the identification using the public key of the peer
            PKCS1EncryptedISAKMPPayload pke = new PKCS1EncryptedISAKMPPayload(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyPKE());
            return pke;
        }
        if (ciphersuite.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            // this authentication method encrypts the identification using a derived key
            result.setIdType(IDTypeEnum.KEY_ID);
            secrets.setIdentificationPayloadBody(result.getBody());
            secrets.computeSecretKeys();
            SymmetricallyEncryptedIdentificationPayloadHuaweiStyle rpke = new SymmetricallyEncryptedIdentificationPayloadHuaweiStyle(result, ciphersuite, new SecretKeySpec(secrets.getKe_i(), ciphersuite.getCipher().cipherJCEName()), secrets.getRPKEIV());
            rpke.encrypt();
            secrets.setRPKEIV(rpke.getNextIV());
            return rpke;
        }
        return result;
    }

    public ISAKMPPayload prepareNoncePayload(byte[] msgID) throws GeneralSecurityException {
        NoncePayload result = new NoncePayload();
        SecurityAssociationSecrets sas = this.secrets.getSA(msgID);
        if (sas.getInitiatorNonce() == null) {
            SecureRandom random = new SecureRandom();
            byte[] initiatorNonce = new byte[ciphersuite.getNonceLen()];
            random.nextBytes(initiatorNonce);
            sas.setInitiatorNonce(initiatorNonce);
        }
        result.setNonceData(sas.getInitiatorNonce());
        // these authentication methods encrypt the nonce using the public key of the peer
        if (Arrays.equals(msgID, new byte[4]) && ciphersuite.getAuthMethod() == AuthAttributeEnum.PKE) {
            PKCS1EncryptedISAKMPPayload pke = new PKCS1EncryptedISAKMPPayload(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyPKE());
            return pke;
        }
        if (Arrays.equals(msgID, new byte[4]) && ciphersuite.getAuthMethod() == AuthAttributeEnum.RevPKE) {
            PKCS1EncryptedISAKMPPayload rpke = new PKCS1EncryptedISAKMPPayload(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKeyRPKE());
            return rpke;
        }
        return result;
    }

    public ISAKMPPayload preparePhase1HashPayload() throws GeneralSecurityException, IOException {
        HashPayload hashPayload = new HashPayload();
        hashPayload.setHashData(secrets.getHASH_I());
        return hashPayload;
    }

    public ISAKMPPayload prepareDeletePayload() throws GeneralSecurityException, IOException {
        DeletePayload deletePayload = new DeletePayload();
        byte[] concatCookies = new byte[ISAKMPMessage.COOKIE_LEN * 2];
        if (secrets.getInitiatorCookie() != null) {
            System.arraycopy(secrets.getInitiatorCookie(), 0, concatCookies, 0, ISAKMPMessage.COOKIE_LEN);
        }
        if (secrets.getResponderCookie() != null) {
            System.arraycopy(secrets.getResponderCookie(), 0, concatCookies, ISAKMPMessage.COOKIE_LEN, ISAKMPMessage.COOKIE_LEN);
        }
        deletePayload.addSPI(concatCookies);
        return deletePayload;
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
