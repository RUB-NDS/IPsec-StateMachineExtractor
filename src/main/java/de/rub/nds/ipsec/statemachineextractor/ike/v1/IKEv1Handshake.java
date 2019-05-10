/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.IKEDHGroupEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.HashPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.KeyExchangePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.NoncePayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
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
import java.security.spec.ECPoint;
import java.security.spec.KeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEDHPublicKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;

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

    // The default "ciphersuite"
    IKEv1Attribute.Auth authMethod = IKEv1Attribute.Auth.PSK;
    IKEv1Attribute.Hash hash = IKEv1Attribute.Hash.MD5;
    IKEDHGroupEnum group = IKEDHGroupEnum.GROUP1_768;
    int nonceLen = 8;

    public IKEv1Handshake(long timeout, InetAddress remoteAddress, int port) {
        this.udpTH = new LoquaciousClientUdpTransportHandler(timeout, remoteAddress.getHostAddress(), port);
    }

    public ISAKMPMessage exchangeMessage(ISAKMPMessage messageToSend) throws IOException, ISAKMPParsingException {
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
        responderCookie = messageReceived.getResponderCookie();
        return messageReceived;
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
        if (group.isEC()) {
            result = prepareECKeyExchangePayload();
        } else {
            result = prepareModPKeyExchangePayload();
        }
        keyExchangeData = result.getKeyExchangeData();
        return result;
    }

    protected KeyExchangePayload prepareModPKeyExchangePayload() throws GeneralSecurityException {
        generateDHKeyPairIfNecessary("DiffieHellman");
        KeyExchangePayload result = new KeyExchangePayload();
        byte[] publicKeyBytes = ((JCEDHPublicKey) dhKeyPair.getPublic()).getY().toByteArray();
        if (publicKeyBytes[0] != 0) {
            result.setKeyExchangeData(publicKeyBytes);
        } else {
            byte[] shortPublicKeyBytes = new byte[publicKeyBytes.length - 1];
            System.arraycopy(publicKeyBytes, 1, shortPublicKeyBytes, 0, publicKeyBytes.length - 1);
            result.setKeyExchangeData(shortPublicKeyBytes);
        }
        return result;
    }

    protected KeyExchangePayload prepareECKeyExchangePayload() throws GeneralSecurityException {
        generateDHKeyPairIfNecessary("EC");
        KeyExchangePayload result = new KeyExchangePayload();
        ECPoint w = ((JCEECPublicKey) dhKeyPair.getPublic()).getW();
        byte[] publicKeyBytes = new byte[group.getPublicKeySizeInBytes()];
        int paramLen = group.getPublicKeySizeInBytes() / 2;
        byte[] wx = w.getAffineX().toByteArray();
        int start = (wx[0] == 0 && wx.length == paramLen + 1) ? 1 : 0;
        System.arraycopy(wx, start, publicKeyBytes, 0, paramLen);
        byte[] wy = w.getAffineY().toByteArray();
        start = (wy[0] == 0 && wy.length == paramLen + 1) ? 1 : 0;
        System.arraycopy(wy, start, publicKeyBytes, paramLen, paramLen);
        result.setKeyExchangeData(publicKeyBytes);
        return result;
    }
    
    private void generateDHKeyPairIfNecessary(String algoName) throws GeneralSecurityException {
        if (dhKeyPair == null) {
            KeyPairGenerator keyPairGen;
            keyPairGen = KeyPairGenerator.getInstance(algoName, BouncyCastleProvider.PROVIDER_NAME);
            keyPairGen.initialize(group.getAlgorithmParameterSpec());
            dhKeyPair = keyPairGen.generateKeyPair();
        }
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
            initiatorNonce = new byte[nonceLen];
            random.nextBytes(initiatorNonce);
        }
        result.setNonceData(initiatorNonce);
        return result;
    }

    public HashPayload prepareHashPayload() throws GeneralSecurityException, IOException {
        if (skeyid == null) {
            computeSKEYID();
        }
        Mac prf = Mac.getInstance("Hmac" + hash.toString());
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
        Mac prf = Mac.getInstance("Hmac" + hash.toString());
        SecretKeyFactory skf = SecretKeyFactory.getInstance("Hmac" + hash.toString());
        KeySpec spec;
        SecretKey hmacKey;
        byte[] skeyidBytes;
        if (dhSecret == null) {
            computeDHSecret();
        }
        byte[] concatNonces = new byte[initiatorNonce.length + responderNonce.length];
        System.arraycopy(initiatorNonce, 0, concatNonces, 0, initiatorNonce.length);
        System.arraycopy(responderNonce, 0, concatNonces, initiatorNonce.length, responderNonce.length);
        switch (authMethod) {
            case RSA_Sig:
            case DSS_Sig: // For signatures: SKEYID = prf(Ni_b | Nr_b, g^xy)
                spec = new SecretKeySpec(concatNonces, "Hmac" + hash.toString());
                hmacKey = skf.generateSecret(spec);
                prf.init(hmacKey);
                skeyidBytes = prf.doFinal(dhSecret);
                break;

            case PKE:
            case RevPKE: // For public key encryption: SKEYID = prf(hash(Ni_b | Nr_b), CKY-I | CKY-R)
                MessageDigest digest = MessageDigest.getInstance(mapHashName(hash));
                spec = new SecretKeySpec(digest.digest(concatNonces), "Hmac" + hash.toString());
                hmacKey = skf.generateSecret(spec);
                prf.init(hmacKey);
                byte[] concatCookies = new byte[16];
                System.arraycopy(initiatorCookie, 0, concatCookies, 0, 8);
                System.arraycopy(responderNonce, 0, concatCookies, 8, 8);
                skeyidBytes = prf.doFinal(concatCookies);
                break;

            case PSK: // For pre-shared keys: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
                spec = new SecretKeySpec(preSharedKey, "Hmac" + hash.toString());
                hmacKey = skf.generateSecret(spec);
                prf.init(hmacKey);
                skeyidBytes = prf.doFinal(concatNonces);
                break;
            default:
                throw new UnsupportedOperationException("Unknown authMethod.");
        }
        spec = new SecretKeySpec(skeyidBytes, "Hmac" + hash.toString());
        skeyid = skf.generateSecret(spec);
    }

    private void computeDHSecret() throws GeneralSecurityException {
        String keyAlgoName, dhAlgoName;
        if (group.isEC()) {
            keyAlgoName = "EC";
            dhAlgoName = "ECDH";
        } else {
            keyAlgoName = dhAlgoName = "DiffieHellman";
        }
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(keyAlgoName);
        keyPairGen.initialize(group.getAlgorithmParameterSpec());
        KeyAgreement keyAgreement = KeyAgreement.getInstance(dhAlgoName);
        keyAgreement.init(dhKeyPair.getPrivate());
        keyAgreement.doPhase(otherPublicKey, true);
        dhSecret = keyAgreement.generateSecret();
    }

    private static String mapHashName(IKEv1Attribute.Hash hash) {
        switch (hash) {
            case SHA1:
                return "SHA-1";
            default:
                return hash.toString();
        }
    }
}
