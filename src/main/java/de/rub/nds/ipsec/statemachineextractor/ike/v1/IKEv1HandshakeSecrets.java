/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
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
class IKEv1HandshakeSecrets {

    static final int COOKIE_LEN = 8;

    private byte[] preSharedKey = new byte[]{};
    private byte[] initiatorCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] responderCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private KeyPair dhKeyPair;
    private PublicKey peerPublicKey;
    private byte[] dhSecret;
    private byte[] initiatorNonce = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] responderNonce = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private SecretKey skeyid;
    private byte[] keyExchangeData;
    private byte[] identificationPayloadBody;
    private byte[] peerKeyExchangeData;
    private byte[] peerIdentificationPayloadBody;

    private final IKEv1Ciphersuite ciphersuite;

    public IKEv1HandshakeSecrets(IKEv1Ciphersuite ciphersuite) {
        this.ciphersuite = ciphersuite;
    }

    public byte[] getPreSharedKey() {
        return preSharedKey;
    }

    public void setPreSharedKey(byte[] preSharedKey) {
        this.preSharedKey = preSharedKey;
    }

    public byte[] getInitiatorCookie() {
        return initiatorCookie;
    }

    public void setInitiatorCookie(byte[] initiatorCookie) {
        this.initiatorCookie = initiatorCookie;
    }

    public byte[] getResponderCookie() {
        return responderCookie;
    }

    public void setResponderCookie(byte[] responderCookie) {
        this.responderCookie = responderCookie;
    }

    public KeyPair getDhKeyPair() {
        return dhKeyPair;
    }

    public void setDhKeyPair(KeyPair dhKeyPair) {
        this.dhKeyPair = dhKeyPair;
    }

    public KeyPair generateDhKeyPair() throws GeneralSecurityException {
        String algoName;
        if (ciphersuite.getDhGroup().getDHGroupParameters().isEC()) {
            algoName = "EC";
        } else {
            algoName = "DiffieHellman";
        }
        this.dhKeyPair = CryptoHelper.generateKeyPair(algoName, ciphersuite.getDhGroup().getDHGroupParameters().getAlgorithmParameterSpec());
        return dhKeyPair;
    }

    public PublicKey getPeerPublicKey() {
        return peerPublicKey;
    }

    public void setPeerPublicKey(PublicKey peerPublicKey) {
        this.peerPublicKey = peerPublicKey;
    }

    public PublicKey computePeerPublicKey() throws GeneralSecurityException {
        if (this.peerKeyExchangeData == null) {
            throw new IllegalStateException("No key exchange data for peer; use setPeerKeyExchangeData() first!");
        }
        if (ciphersuite.getDhGroup().getDHGroupParameters().isEC()) {
            ECParameterSpec algoSpec = (ECParameterSpec) ciphersuite.getDhGroup().getDHGroupParameters().getAlgorithmParameterSpec();
            peerPublicKey = CryptoHelper.createECPublicKeyFromBytes(algoSpec, this.peerKeyExchangeData);
        } else {
            DHParameterSpec algoSpec = (DHParameterSpec) ciphersuite.getDhGroup().getDHGroupParameters().getAlgorithmParameterSpec();
            peerPublicKey = CryptoHelper.createModPPublicKeyFromBytes(algoSpec, this.peerKeyExchangeData);
        }
        return this.peerPublicKey;
    }

    public byte[] getDHSecret() {
        return dhSecret;
    }

    public void setDHSecret(byte[] dhSecret) {
        this.dhSecret = dhSecret;
    }

    public byte[] computeDHSecret() throws GeneralSecurityException, IllegalStateException {
        if (dhKeyPair == null) {
            throw new IllegalStateException("No keypair generated; use generateDhKeyPair() first!");
        }
        if (peerPublicKey == null) {
            try {
                computePeerPublicKey();
            } catch (IllegalStateException ex) {
                throw new IllegalStateException("No public key for peer; use setPeerPublicKey() or setPeerKeyExchangeData() first!", ex);
            }
        }
        String dhAlgoName;
        if (ciphersuite.getDhGroup().getDHGroupParameters().isEC()) {
            dhAlgoName = "ECDH";
        } else {
            dhAlgoName = "DiffieHellman";
        }
        KeyAgreement keyAgreement = KeyAgreement.getInstance(dhAlgoName);
        keyAgreement.init(dhKeyPair.getPrivate());
        keyAgreement.doPhase(peerPublicKey, true);
        this.dhSecret = keyAgreement.generateSecret();
        return this.dhSecret;
    }

    public byte[] getInitiatorNonce() {
        return initiatorNonce;
    }

    public void setInitiatorNonce(byte[] initiatorNonce) {
        this.initiatorNonce = initiatorNonce;
    }

    public byte[] getResponderNonce() {
        return responderNonce;
    }

    public void setResponderNonce(byte[] responderNonce) {
        this.responderNonce = responderNonce;
    }

    public SecretKey getSKEYID() {
        return skeyid;
    }

    public void setSKEYID(SecretKey skeyid) {
        this.skeyid = skeyid;
    }

    public SecretKey computeSKEYID() throws GeneralSecurityException {
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
                byte[] concatCookies = new byte[COOKIE_LEN * 2];
                System.arraycopy(initiatorCookie, 0, concatCookies, 0, COOKIE_LEN);
                System.arraycopy(responderNonce, 0, concatCookies, 8, COOKIE_LEN);
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
        return skeyid;
    }

    public byte[] getKeyExchangeData() {
        return keyExchangeData;
    }

    public void setKeyExchangeData(byte[] keyExchangeData) {
        this.keyExchangeData = keyExchangeData;
    }

    public byte[] generateKeyExchangeData() throws GeneralSecurityException {
        if (dhKeyPair == null) {
            generateDhKeyPair();
        }
        this.keyExchangeData = CryptoHelper.publicKey2Bytes(dhKeyPair.getPublic());
        return this.keyExchangeData;
    }

    public byte[] getIdentificationPayloadBody() {
        return identificationPayloadBody;
    }

    public void setIdentificationPayloadBody(byte[] identificationPayloadBody) {
        this.identificationPayloadBody = identificationPayloadBody;
    }

    public byte[] getPeerKeyExchangeData() {
        return peerKeyExchangeData;
    }

    public void setPeerKeyExchangeData(byte[] peerKeyExchangeData) {
        this.peerKeyExchangeData = peerKeyExchangeData;
    }

    public byte[] getPeerIdentificationPayloadBody() {
        return peerIdentificationPayloadBody;
    }

    public void setPeerIdentificationPayloadBody(byte[] peerIdentificationPayloadBody) {
        this.peerIdentificationPayloadBody = peerIdentificationPayloadBody;
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
