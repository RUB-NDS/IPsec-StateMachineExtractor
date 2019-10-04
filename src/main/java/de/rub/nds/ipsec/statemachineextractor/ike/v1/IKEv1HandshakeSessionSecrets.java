/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeSessionSecrets {

    static final int COOKIE_LEN = 8;

    private boolean isInitiatorCookieChosen = false;
    private byte[] initiatorCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] responderCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private KeyPair dhKeyPair;
    private PublicKey peerPublicKey;
    private byte[] dhSecret;
    private byte[] iv;
    private DHGroupAttributeEnum internalDHGroup;
    private boolean isInitiatorNonceChosen = false;
    private byte[] initiatorNonce = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] responderNonce = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private SecretKeySpec skeyid, skeyid_d, skeyid_a, skeyid_e;
    private byte[] securityAssociationOfferBody;
    private byte[] keyExchangeData;
    private byte[] identificationPayloadBody;
    private byte[] peerKeyExchangeData;
    private byte[] peerIdentificationPayloadBody;

    private final IKEv1Ciphersuite ciphersuite;
    private final IKEv1HandshakeLongtermSecrets ltsecrets;

    public IKEv1HandshakeSessionSecrets(IKEv1Ciphersuite ciphersuite, IKEv1HandshakeLongtermSecrets ltsecrets) {
        this.ciphersuite = ciphersuite;
        this.ltsecrets = ltsecrets;
    }

    public void generateDefaults() throws GeneralSecurityException {
        generateDhKeyPair();
        setPeerKeyExchangeData(CryptoHelper.publicKey2Bytes(dhKeyPair.getPublic()));
        computePeerPublicKey();
        generateDhKeyPair();
        computeDHSecret();
        computeSecretKeys();
    }

    public byte[] getInitiatorCookie() {
        if (!isInitiatorCookieChosen) {
            return null;
        }
        return initiatorCookie;
    }

    public void setInitiatorCookie(byte[] initiatorCookie) {
        this.initiatorCookie = initiatorCookie;
        isInitiatorCookieChosen = true;
    }

    public byte[] getResponderCookie() {
        return responderCookie;
    }

    public void setResponderCookie(byte[] responderCookie) {
        this.responderCookie = responderCookie;
    }

    public DHGroupAttributeEnum getInternalDHGroup() {
        return internalDHGroup;
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
        this.internalDHGroup = ciphersuite.getDhGroup();
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
            throw new IllegalStateException("No key pair generated; use generateDhKeyPair() first!");
        }
        if (this.internalDHGroup != ciphersuite.getDhGroup()) {
            throw new IllegalStateException("The existing key pair does not match the ciphersuite!");
        }
        try {
            computePeerPublicKey();
        } catch (IllegalStateException ex) {
            throw new IllegalStateException("No public key for peer; use setPeerPublicKey() or setPeerKeyExchangeData() first!", ex);
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
        if (!isInitiatorNonceChosen) {
            return null;
        }
        return initiatorNonce;
    }

    public void setInitiatorNonce(byte[] initiatorNonce) {
        this.initiatorNonce = initiatorNonce;
        isInitiatorNonceChosen = true;
    }

    public byte[] getResponderNonce() {
        return responderNonce;
    }

    public void setResponderNonce(byte[] responderNonce) {
        this.responderNonce = responderNonce;
    }

    public SecretKeySpec getSKEYID() {
        return skeyid;
    }

    public SecretKeySpec getSKEYID_d() {
        return skeyid_d;
    }

    public SecretKeySpec getSKEYID_a() {
        return skeyid_a;
    }

    public SecretKeySpec getSKEYID_e() {
        return skeyid_e;
    }

    public void computeSecretKeys() throws GeneralSecurityException {
        Mac prf = Mac.getInstance("Hmac" + ciphersuite.getHash().toString());
        SecretKeySpec hmacKey;
        byte[] skeyidBytes, skeyid_dBytes, skeyid_aBytes, skeyid_eBytes;
        computeDHSecret();
        byte[] concatNonces = new byte[initiatorNonce.length + responderNonce.length];
        System.arraycopy(initiatorNonce, 0, concatNonces, 0, initiatorNonce.length);
        System.arraycopy(responderNonce, 0, concatNonces, initiatorNonce.length, responderNonce.length);
        byte[] concatCookies = new byte[COOKIE_LEN * 2];
        System.arraycopy(initiatorCookie, 0, concatCookies, 0, COOKIE_LEN);
        System.arraycopy(responderNonce, 0, concatCookies, COOKIE_LEN, COOKIE_LEN);
        switch (ciphersuite.getAuthMethod()) {
            case RSA_Sig:
            case DSS_Sig: // For signatures: SKEYID = prf(Ni_b | Nr_b, g^xy)
                hmacKey = new SecretKeySpec(concatNonces, "Hmac" + ciphersuite.getHash().toString());
                prf.init(hmacKey);
                skeyidBytes = prf.doFinal(dhSecret);
                break;

            case PKE:
            case RevPKE: // For public key encryption: SKEYID = prf(hash(Ni_b | Nr_b), CKY-I | CKY-R)
                MessageDigest digest = MessageDigest.getInstance(mapHashName(ciphersuite.getHash()));
                hmacKey = new SecretKeySpec(digest.digest(concatNonces), "Hmac" + ciphersuite.getHash().toString());
                prf.init(hmacKey);
                skeyidBytes = prf.doFinal(concatCookies);
                break;

            case PSK: // For pre-shared keys: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
                hmacKey = new SecretKeySpec(ltsecrets.getPreSharedKey(), "Hmac" + ciphersuite.getHash().toString());
                prf.init(hmacKey);
                skeyidBytes = prf.doFinal(concatNonces);
                break;

            default:
                throw new UnsupportedOperationException("Unknown authMethod.");
        }
        skeyid = new SecretKeySpec(skeyidBytes, "Hmac" + ciphersuite.getHash().toString());
        prf.init(skeyid);
        prf.update(this.getDHSecret());
        prf.update(concatCookies);
        prf.update((byte) 0);
        skeyid_dBytes = prf.doFinal();
        prf.update(skeyid_dBytes);
        prf.update(this.getDHSecret());
        prf.update(concatCookies);
        prf.update((byte) 1);
        skeyid_aBytes = prf.doFinal();
        prf.update(skeyid_aBytes);
        prf.update(this.getDHSecret());
        prf.update(concatCookies);
        prf.update((byte) 2);
        skeyid_eBytes = prf.doFinal();
        skeyid_d = new SecretKeySpec(skeyid_dBytes, "Hmac" + ciphersuite.getHash().toString()); // FIXME:
        skeyid_a = new SecretKeySpec(skeyid_aBytes, "Hmac" + ciphersuite.getHash().toString()); // FIXME:
        byte[] skeyid_eBytesBlockSize = new byte[ciphersuite.getCipher().getBlockSize()];
        System.arraycopy(skeyid_eBytes, 0, skeyid_eBytesBlockSize, 0, skeyid_eBytesBlockSize.length);
        skeyid_e = new SecretKeySpec(skeyid_eBytesBlockSize, ciphersuite.getCipher().cipherJCEName());
    }

    public byte[] getHASH_I() throws GeneralSecurityException {
        if (this.getSKEYID() == null) {
            this.computeSecretKeys();
        }
        Mac prf = Mac.getInstance("Hmac" + ciphersuite.getHash().toString());
        prf.init(this.getSKEYID());
        prf.update(this.getKeyExchangeData());
        prf.update(this.getPeerKeyExchangeData());
        prf.update(this.initiatorCookie);
        prf.update(this.responderCookie);
        prf.update(this.securityAssociationOfferBody);
        return prf.doFinal(this.getIdentificationPayloadBody());
    }

    public byte[] getHASH_R() throws GeneralSecurityException {
        if (this.getSKEYID() == null) {
            this.computeSecretKeys();
        }
        Mac prf = Mac.getInstance("Hmac" + ciphersuite.getHash().toString());
        prf.init(this.getSKEYID());
        prf.update(this.getPeerKeyExchangeData());
        prf.update(this.getKeyExchangeData());
        prf.update(this.getResponderCookie());
        prf.update(this.getInitiatorCookie());
        prf.update(this.securityAssociationOfferBody);
        return prf.doFinal(this.getPeerIdentificationPayloadBody());
    }

    public byte[] getIV() throws GeneralSecurityException {
        if (this.iv == null) {
            int blockSize = ciphersuite.getCipher().getBlockSize();
            try {
                MessageDigest digest = MessageDigest.getInstance(mapHashName(ciphersuite.getHash()));
                digest.update(this.getKeyExchangeData());
                digest.update(this.getPeerKeyExchangeData());
                byte[] hash = digest.digest();
                this.iv = new byte[blockSize];
                System.arraycopy(hash, 0, this.iv, 0, blockSize);
            } catch (NullPointerException ex) {
                return new byte[blockSize];
            }
        }
        return this.iv;
    }

    public void setIV(byte[] iv) {
        this.iv = iv.clone();
    }

    public void setSAOfferBody(byte[] securityAssociationOfferBody) {
        this.securityAssociationOfferBody = securityAssociationOfferBody;
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
