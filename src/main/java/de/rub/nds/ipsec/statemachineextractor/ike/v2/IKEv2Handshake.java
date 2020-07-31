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
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.DeletePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.IdentificationPayloadInitiator;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.IdentificationPayloadResponder;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.AuthenticationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.AUTHMethodEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.TrafficSelectorPayloadResponder;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.TrafficSelectorPayloadInitiator;
import de.rub.nds.ipsec.statemachineextractor.isakmp.EncryptedISAKMPMessagev2;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ExchangeTypeEnum;
//mport de.rub.nds.ipsec.statemachineextractor.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.ISAKMPMessagev2;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.NotificationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
//import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.KeyExchangePayloadv2;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.NoncePayloadv2;
//import de.rub.nds.ipsec.statemachineextractor.isakmp.PKCS1EncryptedISAKMPPayload;
//import de.rub.nds.ipsec.statemachineextractor.isakmp.NotificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.ProposalPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.SecurityAssociationPayloadv2;
//import de.rub.nds.ipsec.statemachineextractor.isakmp.SymmetricallyEncryptedISAKMPPayload;
//import de.rub.nds.ipsec.statemachineextractor.isakmp.SymmetricallyEncryptedIdentificationPayloadHuaweiStyle;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.TransformPayloadv2;
//import de.rub.nds.ipsec.statemachineextractor.isakmp.VendorIDPayload;
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

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public final class IKEv2Handshake {

    LoquaciousClientUdpTransportHandler udpTH;
    IKEv2Ciphersuite ciphersuite;
    IKEv2HandshakeLongtermSecrets ltsecrets;
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

    public ISAKMPMessagev2 exchangeMessage(ISAKMPMessagev2 messageToSend) throws IOException, ISAKMPParsingException, GeneralSecurityException, IKEHandshakeException {
        if (secrets.getInitiatorCookie() == null) {
            secrets.setInitiatorCookie(messageToSend.getInitiatorCookie());
        } else {
            messageToSend.setInitiatorCookie(secrets.getInitiatorCookie());
        }
        messageToSend.setResponderCookie(secrets.getResponderCookie());
        if (messageToSend.getNextPayload() == PayloadTypeEnum.SecurityAssociationv2 && secrets.getISAKMPSA().getSAOfferBody() == null) {
            secrets.getISAKMPSA().setSAOfferBody(messageToSend.getPayloads().get(0).getBody());
        }
        byte[] txData = messageToSend.getBytes();
        messages.add(new WireMessage(txData, messageToSend, true));
        byte[] rxData = exchangeData(txData);
        if (rxData == null) {
            return null;
        }
        ISAKMPMessagev2 messageReceived = ISAKMPMessageFromByteArray(rxData);
        messages.add(new WireMessage(rxData, messageReceived, false));
        return messageReceived;
    }

    ISAKMPMessagev2 ISAKMPMessageFromByteArray(byte[] bytes) throws ISAKMPParsingException, GeneralSecurityException, IKEHandshakeException, IOException {
        if (bytes.length < ISAKMPMessagev2.ISAKMP_HEADER_LEN) {
            throw new ISAKMPParsingException("Not enough bytes supplied to build an ISAKMPMessage!");
        }
        switch (ExchangeTypeEnum.get(bytes[18])) {
            case IKE_SA_INIT:
            case IKE_AUTH:
                break;
            default:
                throw new UnsupportedOperationException("Not supported yet.");
        }
        ISAKMPMessagev2 message = new ISAKMPMessagev2();
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
        bais.skip(ISAKMPMessagev2.ISAKMP_HEADER_LEN);
        PayloadTypeEnum nextPayload = PayloadTypeEnum.get(bytes[16]);
        if (nextPayload == PayloadTypeEnum.EncryptedAndAuthenticated) {
        	processEncryptedMessage(message, nextPayload, bais);
        } else {
            processPlainMessage(message, nextPayload, bais);
        }
        //if (messageLength != message.getLength()) {
          //  throw new ISAKMPParsingException("Message lengths differ - Computed: " + message.getLength() + " vs. Received: " + messageLength + "!");
        //}
        return message;
    }

    private ISAKMPMessagev2 processEncryptedMessage(ISAKMPMessagev2 encMessage, PayloadTypeEnum nextPayload, ByteArrayInputStream bais) throws GeneralSecurityException, ISAKMPParsingException, IKEHandshakeException {
    	SecretKeySpec ENCRkey = new SecretKeySpec(secrets.getSKer(), ciphersuite.getCipher().cipherJCEName());
        byte[] iv = secrets.getIV(encMessage.getMessageId());
        byte[] INTEGkey = secrets.getSKar();
        EncryptedISAKMPMessagev2 decMessage = EncryptedISAKMPMessagev2.fromPlainMessage(encMessage, ENCRkey, ciphersuite.getCipher(), iv, INTEGkey, ciphersuite.getAuthMethod());
        decMessage.setCiphertext(bais);
        decMessage.setNextPayload(nextPayload);
        decMessage.decrypt();
        /**
        PayloadTypeEnum payloadType = nextPayload;
        for (ISAKMPPayload payload : decMessage.getPayloads()) {
            switch (payloadType) {
                case SecurityAssociation:
                    SecurityAssociationPayload sa = (SecurityAssociationPayload) payload;
                    if (sa.getProposalPayloads().size() != 1) {
                        throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
                    }processEncyptedMessage
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
        **/
    	return null;
    }

    private void processPlainMessage(ISAKMPMessagev2 message, PayloadTypeEnum nextPayload, ByteArrayInputStream bais) throws ISAKMPParsingException, GeneralSecurityException, IllegalStateException, UnsupportedOperationException, IKEHandshakeException, IOException {
        ISAKMPPayload payload;
        while (nextPayload != PayloadTypeEnum.NONE) {
            switch (nextPayload) {
                case SecurityAssociationv2:
                    payload = SecurityAssociationPayloadv2.fromStream(bais);
                    SecurityAssociationPayloadv2 receivedSAPayload = (SecurityAssociationPayloadv2) payload;
                    //adjustCiphersuite(receivedSAPayload);
                    break;
                case KeyExchangev2:
                    switch (ciphersuite.getAuthMethod()) {
                        //case RevPKE:
                          //  SecretKeySpec ke_r = new SecretKeySpec(secrets.getKe_r(), ciphersuite.getCipher().cipherJCEName());
                           // SymmetricallyEncryptedISAKMPPayload symmPayload = SymmetricallyEncryptedISAKMPPayload.fromStream(KeyExchangePayload.class, bais, ciphersuite, ke_r, secrets.getRPKEIV());
                            //secrets.getISAKMPSA().setPeerKeyExchangeData(((KeyExchangePayload) symmPayload.getUnderlyingPayload()).getKeyExchangeData());
                            //payload = symmPayload;
                            //break;
                        default:
                            payload = KeyExchangePayloadv2.fromStream(bais);
                            secrets.getISAKMPSA().setPeerKeyExchangeData(((KeyExchangePayloadv2) payload).getKeyExchangeData());
                            break;
                    }
                    secrets.getISAKMPSA().computeDHSecret();
                    break;
                /**
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
                                PKCS1EncryptedISAKMPPayload pkcs1Payload = PKCS1EncryptedISAKMPPayload.fromStream(IdentificationPayload.class, bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey());
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
                **/
                case Noncev2:
                    switch (ciphersuite.getAuthMethod()) {
                        /**
                    	case PKE:
                        case RevPKE:
                            bais.mark(0);
                            try {
                                PKCS1EncryptedISAKMPPayload encPayload = PKCS1EncryptedISAKMPPayload.fromStream(NoncePayload.class, bais, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey());
                                secrets.getISAKMPSA().setResponderNonce(((NoncePayload) encPayload.getUnderlyingPayload()).getNonceData());
                                payload = encPayload;
                                break; // only executed when there's no exception
                            } catch (ISAKMPParsingException ex) {
                                if (!(ex.getCause() instanceof BadPaddingException)) {
                                    throw ex;
                                }
                                // Payload was probably not encrypted, let's use the default case
                                bais.reset();
                            }
                            **/
                        default:
                        	payload = NoncePayloadv2.fromStream(bais);
                            secrets.getISAKMPSA().setResponderNonce(((NoncePayloadv2) payload).getNonceData());
                            break;
                    }
                    secrets.computeSecretKeys();
                    break;
                    /**
                case VendorID:
                    payload = VendorIDPayload.fromStream(bais);
                    break;
                    **/
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
        ltsecrets = new IKEv2HandshakeLongtermSecrets();
        secrets = new IKEv2HandshakeSessionSecrets(ciphersuite, ltsecrets);
        if (this.udpTH != null) {
            dispose();
        }
        this.udpTH = new LoquaciousClientUdpTransportHandler(this.timeout, this.remoteAddress.getHostAddress(), this.remotePort);
        //prepareIdentificationPayload(); // sets secrets.identificationPayloadBody
        //secrets.setPeerIdentificationPayloadBody(secrets.getIdentificationPayloadBody()); // only a default
        //secrets.getISAKMPSA().setSAOfferBody(null);
        secrets.generateDefaults();
    }
    
    public ISAKMPMessagev2 Phase1() throws IOException, GeneralSecurityException, ISAKMPParsingException, IKEHandshakeException {
    	byte[] msgID = DatatypeHelper.hexDumpToByteArray("00000000");
    	ISAKMPMessagev2 msg = new ISAKMPMessagev2();
        ISAKMPPayload SAv2 = preparePhase1SecurityAssociation();
        ISAKMPPayload KEv2 = prepareKeyExchangePayload(msgID);
        ISAKMPPayload NOv2 = prepareNoncePayload(msgID);
        msg.addPayload(SAv2);
    	msg.addPayload(KEv2);
    	msg.addPayload(NOv2);
    	msg.setExchangeType(ExchangeTypeEnum.IKE_SA_INIT);
        msg.setInitiatorFlag(true);
        msg.setVersionFlag(false);
        msg.setResponseFlag(false);
    	return exchangeMessage(msg);
    }
    
    public ISAKMPMessagev2 Phase2() throws IOException, GeneralSecurityException, ISAKMPParsingException, IKEHandshakeException {
    	byte[] msgID = DatatypeHelper.hexDumpToByteArray("00000001"); //implement as messages divided by 2
    	secrets.setMessage(messages.get(0).getMessage().getBytes());
    	ISAKMPMessagev2 msg = new ISAKMPMessagev2();
    	ISAKMPPayload IDinit = prepareIdentificationInitiator();
    	secrets.computeOctets();
    	ISAKMPPayload AUTH = prepareAuthenticationPayload();
    	ISAKMPPayload SA2 = preparePhase2SecurityAssociation();
    	ISAKMPPayload TSi = prepareTrafficSelectorPayloadInitiator();
    	ISAKMPPayload TSr = prepareTrafficSelectorPayloadResponder();
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
        EncryptedISAKMPMessagev2 ENCmsg = EncryptedISAKMPMessagev2.fromPlainMessage(msg, ENCRkey, ciphersuite.getCipher(), iv, secrets.getSKai(), ciphersuite.getAuthMethod());   
    	return exchangeMessage(ENCmsg);
    }
/**
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
**/
    public void dispose() throws IOException {
        if (udpTH.isInitialized()) {
            udpTH.closeConnection();
        }
    }
    
    public ISAKMPPayload preparePhase1SecurityAssociation() {
    	return SecurityAssociationPayloadFactoryv2.P1_AES_128_CBC_SHA1;
    }
    
    public ISAKMPPayload preparePhase2SecurityAssociation() {
    	return SecurityAssociationPayloadFactoryv2.P2_AES_128_CBC_SHA1_ESN;
    }
    
    public byte[] getMostRecentMessageID() {
        return secrets.getMostRecentMessageID();
    }

    public void setMostRecentMessageID(byte[] mostRecentMessageID) {
        secrets.setMostRecentMessageID(mostRecentMessageID);
    }
    
  /**
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
**/
    public ISAKMPPayload prepareKeyExchangePayload(byte[] msgID) throws GeneralSecurityException, ISAKMPParsingException {
    	SecurityAssociationSecrets sas = this.secrets.getSA(msgID);
        KeyExchangePayloadv2 result = new KeyExchangePayloadv2(sas.getDHGroup());
        //System.out.println(new String(sas.generateKeyExchangeData(), 0));
        result.setKeyExchangeData(sas.generateKeyExchangeData());
        result.configureBody();
        return result;
    }
/**
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
            PKCS1EncryptedISAKMPPayload pke = new PKCS1EncryptedISAKMPPayload(result, ltsecrets.getMyPrivateKey(), ltsecrets.getPeerPublicKey());
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
**/
    public ISAKMPPayload prepareNoncePayload(byte[] msgID) throws GeneralSecurityException {
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
/**
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
    **/
    
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
    	result.setAuthMethod(AUTHMethodEnum.PSK);
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
