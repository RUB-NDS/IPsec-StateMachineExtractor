/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.IKEv1Attribute;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEDHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEHandshakeException;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum;
import static de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum.DSS_Sig;
import static de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum.PKE;
import static de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum.PSK;
import static de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum.RevPKE;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum;
import static de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum.SHA1;
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
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.LoquaciousClientUdpTransportHandler;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1Handshake {

    LoquaciousClientUdpTransportHandler udpTH;

    private byte[] preSharedKey = new byte[]{};
    private byte[] initiatorCookie, responderCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private SecurityAssociationPayload securityAssociation = SecurityAssociationPayloadFactory.PSK_DES_MD5_G1;
    private KeyPair dhKeyPair;
    private PublicKey otherPublicKey;
    private byte[] dhSecret;
    private byte[] initiatorNonce, responderNonce = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private SecretKey skeyid;
    private byte[] keyExchangeData = new byte[]{};
    private byte[] otherKeyExchangeData = new byte[]{};
    private byte[] identificationPayloadBody = new byte[]{};
    private byte[] otherIdentificationPayloadBody = new byte[]{};

    IKEv1Ciphersuite ciphersuite = new IKEv1Ciphersuite();

    public IKEv1Handshake(long timeout, InetAddress remoteAddress, int port) {
        this.udpTH = new LoquaciousClientUdpTransportHandler(timeout, remoteAddress.getHostAddress(), port);
    }

    public ISAKMPMessage exchangeMessage(ISAKMPMessage messageToSend) throws IOException, ISAKMPParsingException, GeneralSecurityException, IKEHandshakeException {
        if (!udpTH.isInitialized()) {
            udpTH.initialize();
        }
        if (initiatorCookie == null) {
            initiatorCookie = messageToSend.getInitiatorCookie();
        } else {
            messageToSend.setInitiatorCookie(initiatorCookie);
        }
        messageToSend.setResponderCookie(responderCookie);
        udpTH.sendData(messageToSend.getBytes());
        byte[] rxData = udpTH.fetchData();
        if (rxData.length == 0) {
            throw new IOException("No data received within timeout");
        }
        ISAKMPMessage messageReceived = IKEv1MessageBuilder.fromByteArray(rxData);
        extractProperties(messageReceived);
        return messageReceived;
    }

    void extractProperties(ISAKMPMessage msg) throws GeneralSecurityException, IKEHandshakeException {
        responderCookie = msg.getResponderCookie();
        for (ISAKMPPayload payload : msg.getPayloads()) {
            switch (payload.getType()) {
                case SecurityAssociation:
                    securityAssociation = (SecurityAssociationPayload) payload;
                    if (securityAssociation.getProposalPayloads().size() != 1) {
                        throw new IKEHandshakeException("Wrong number of proposal payloads found. There should only be one.");
                    }
                    ProposalPayload pp = securityAssociation.getProposalPayloads().get(0);
                    if (pp.getTransformPayloads().size() != 1) {
                        throw new IKEHandshakeException("Wrong number of transform payloads found. There should only be one.");
                    }
                    TransformPayload tp = pp.getTransformPayloads().get(0);
                    for (IKEv1Attribute attr : tp.getAttributes()) {
                        if (attr instanceof AuthAttributeEnum) {
                            ciphersuite.setAuthMethod((AuthAttributeEnum)attr);
                        }
                    }
                    break;
                case KeyExchange:
                    KeyExchangePayload otherKeyExchangePayload = (KeyExchangePayload) payload;
                    otherKeyExchangeData = otherKeyExchangePayload.getKeyExchangeData();
                    if (ciphersuite.getDhGroup().getDHGroupParameters().isEC()) {
                        ECParameterSpec algoSpec = (ECParameterSpec) ciphersuite.getDhGroup().getDHGroupParameters().getAlgorithmParameterSpec();
                        otherPublicKey = CryptoHelper.createECPublicKeyFromBytes(algoSpec, otherKeyExchangeData);
                    } else {
                        DHParameterSpec algoSpec = (DHParameterSpec) ciphersuite.getDhGroup().getDHGroupParameters().getAlgorithmParameterSpec();
                        otherPublicKey = CryptoHelper.createModPPublicKeyFromBytes(algoSpec, otherKeyExchangeData);
                    }
                    break;
                case Identification:
                    IdentificationPayload otherIdentificationPayload = (IdentificationPayload) payload;
                    otherIdentificationPayloadBody = otherIdentificationPayload.getBody();
                    break;
                case Nonce:
                    NoncePayload otherNoncePayload = (NoncePayload) payload;
                    responderNonce = otherNoncePayload.getNonceData();
                    break;
            }
        }
    }

    public void dispose() throws IOException {
        if (udpTH.isInitialized()) {
            udpTH.closeConnection();
        }
    }

    public byte[] getPreSharedKey() {
        return preSharedKey.clone();
    }

    public void setPreSharedKey(byte[] preSharedKey) {
        this.preSharedKey = preSharedKey;
    }

    public KeyExchangePayload prepareKeyExchangePayload() throws GeneralSecurityException {
        KeyExchangePayload result;
        if (ciphersuite.getDhGroup().getDHGroupParameters().isEC()) {
            result = prepareKeyExchangePayload("EC");
        } else {
            result = prepareKeyExchangePayload("DiffieHellman");
        }
        keyExchangeData = result.getKeyExchangeData();
        return result;
    }

    protected KeyExchangePayload prepareKeyExchangePayload(String algoName) throws GeneralSecurityException {
        if (dhKeyPair == null) {
            dhKeyPair = CryptoHelper.generateKeyPair(algoName, ciphersuite.getDhGroup().getDHGroupParameters().getAlgorithmParameterSpec());
        }
        KeyExchangePayload result = new KeyExchangePayload();
        result.setKeyExchangeData(CryptoHelper.publicKey2Bytes(dhKeyPair.getPublic()));
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
        identificationPayloadBody = result.getBody();
        return result;
    }

    public NoncePayload prepareNoncePayload() {
        NoncePayload result = new NoncePayload();
        if (initiatorNonce == null) {
            SecureRandom random = new SecureRandom();
            initiatorNonce = new byte[ciphersuite.getNonceLen()];
            random.nextBytes(initiatorNonce);
        }
        result.setNonceData(initiatorNonce);
        return result;
    }

    public HashPayload prepareHashPayload() throws GeneralSecurityException, IOException {
        if (skeyid == null) {
            computeSKEYID();
        }
        Mac prf = Mac.getInstance("Hmac" + ciphersuite.getHash().toString());
        prf.init(skeyid);
        prf.update(keyExchangeData);
        prf.update(otherKeyExchangeData);
        prf.update(initiatorCookie);
        prf.update(responderCookie);
        prf.update(securityAssociation.getBody());
        byte[] initiatorHash = prf.doFinal(identificationPayloadBody);

        HashPayload result = new HashPayload();
        result.setHashData(initiatorHash);
        return result;
    }

    private void computeSKEYID() throws GeneralSecurityException {
        Mac prf = Mac.getInstance("Hmac" + ciphersuite.getHash().toString());
        SecretKeyFactory skf = SecretKeyFactory.getInstance("Hmac" + ciphersuite.getHash().toString());
        KeySpec spec;
        SecretKey hmacKey;
        byte[] skeyidBytes;
        if (dhSecret == null) {
            computeDHSecret();
        }
        byte[] concatNonces = new byte[initiatorNonce.length + responderNonce.length];
        System.arraycopy(initiatorNonce, 0, concatNonces, 0, initiatorNonce.length);
        System.arraycopy(responderNonce, 0, concatNonces, initiatorNonce.length, responderNonce.length);
        switch (ciphersuite.getAuthMethod()) {
            case RSA_Sig:
            case DSS_Sig: // For signatures: SKEYID = prf(Ni_b | Nr_b, g^xy)
                spec = new SecretKeySpec(concatNonces, "Hmac" + ciphersuite.getHash().toString());
                hmacKey = skf.generateSecret(spec);
                prf.init(hmacKey);
                skeyidBytes = prf.doFinal(dhSecret);
                break;

            case PKE:
            case RevPKE: // For public key encryption: SKEYID = prf(hash(Ni_b | Nr_b), CKY-I | CKY-R)
                MessageDigest digest = MessageDigest.getInstance(mapHashName(ciphersuite.getHash()));
                spec = new SecretKeySpec(digest.digest(concatNonces), "Hmac" + ciphersuite.getHash().toString());
                hmacKey = skf.generateSecret(spec);
                prf.init(hmacKey);
                byte[] concatCookies = new byte[16];
                System.arraycopy(initiatorCookie, 0, concatCookies, 0, 8);
                System.arraycopy(responderNonce, 0, concatCookies, 8, 8);
                skeyidBytes = prf.doFinal(concatCookies);
                break;

            case PSK: // For pre-shared keys: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
                spec = new SecretKeySpec(preSharedKey, "Hmac" + ciphersuite.getHash().toString());
                hmacKey = skf.generateSecret(spec);
                prf.init(hmacKey);
                skeyidBytes = prf.doFinal(concatNonces);
                break;
            default:
                throw new UnsupportedOperationException("Unknown authMethod.");
        }
        spec = new SecretKeySpec(skeyidBytes, "Hmac" + ciphersuite.getHash().toString());
        skeyid = skf.generateSecret(spec);
    }

    private void computeDHSecret() throws GeneralSecurityException {
        String keyAlgoName, dhAlgoName;
        if (ciphersuite.getDhGroup().getDHGroupParameters().isEC()) {
            keyAlgoName = "EC";
            dhAlgoName = "ECDH";
        } else {
            keyAlgoName = dhAlgoName = "DiffieHellman";
        }
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(keyAlgoName);
        keyPairGen.initialize(ciphersuite.getDhGroup().getDHGroupParameters().getAlgorithmParameterSpec());
        KeyAgreement keyAgreement = KeyAgreement.getInstance(dhAlgoName);
        keyAgreement.init(dhKeyPair.getPrivate());
        keyAgreement.doPhase(otherPublicKey, true);
        dhSecret = keyAgreement.generateSecret();
    }

    private static String mapHashName(HashAttributeEnum hash) {
        switch (hash) {
            case SHA1:
                return "SHA-1";
            default:
                return hash.toString();
        }
    }
}
