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
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
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
    private final Map<String, byte[]> IVs = new HashMap<>();
    private final Map<String, SASecrets> SAs = new HashMap<>();
    private byte[] skeyid, skeyid_d, skeyid_a, skeyid_e, ka;
    private byte[] identificationPayloadBody;
    private byte[] peerIdentificationPayloadBody;
    private byte[] mostRecentMessageID;
    private SASecrets ISAKMPSA;

    private final IKEv1Ciphersuite ciphersuite;
    private final IKEv1HandshakeLongtermSecrets ltsecrets;

    public IKEv1HandshakeSessionSecrets(IKEv1Ciphersuite ciphersuite, IKEv1HandshakeLongtermSecrets ltsecrets) {
        this.ciphersuite = ciphersuite;
        this.ltsecrets = ltsecrets;
        updateISAKMPSA();
    }

    public final void updateISAKMPSA() {
        if (this.ISAKMPSA == null || this.ciphersuite.getDhGroup() != this.ISAKMPSA.getDHGroup()) {
            this.ISAKMPSA = new SASecrets(this.ciphersuite.getDhGroup());
            this.SAs.put("00000000", this.ISAKMPSA);
        }
    }

    public SASecrets getISAKMPSA() {
        return ISAKMPSA;
    }

    public void generateDefaults() throws GeneralSecurityException {
        updateISAKMPSA();
        this.ISAKMPSA.generateDhKeyPair();
        this.ISAKMPSA.setPeerKeyExchangeData(CryptoHelper.publicKey2Bytes(this.ISAKMPSA.getDhKeyPair().getPublic()));
        this.ISAKMPSA.computePeerPublicKey();
        this.ISAKMPSA.generateDhKeyPair();
        this.ISAKMPSA.computeDHSecret();
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

    public byte[] getMostRecentMessageID() {
        return mostRecentMessageID;
    }

    public void setMostRecentMessageID(byte[] mostRecentMessageID) {
        this.mostRecentMessageID = mostRecentMessageID;
    }

    public byte[] getSKEYID() {
        return skeyid;
    }

    public byte[] getSKEYID_d() {
        return skeyid_d;
    }

    public byte[] getSKEYID_a() {
        return skeyid_a;
    }

    public byte[] getSKEYID_e() {
        return skeyid_e;
    }

    public byte[] getKa() {
        return ka;
    }

    public void computeSecretKeys() throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getHash().toString();
        Mac prf = Mac.getInstance(HmacIdentifier);
        SecretKeySpec hmacKey;
        byte[] initiatorNonce = this.ISAKMPSA.getInitiatorNonce();
        if (initiatorNonce == null) {
            initiatorNonce = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        }
        byte[] responderNonce = this.ISAKMPSA.getResponderNonce();
        byte[] concatNonces = new byte[initiatorNonce.length + responderNonce.length];
        System.arraycopy(initiatorNonce, 0, concatNonces, 0, initiatorNonce.length);
        System.arraycopy(responderNonce, 0, concatNonces, initiatorNonce.length, responderNonce.length);
        byte[] concatCookies = new byte[COOKIE_LEN * 2];
        System.arraycopy(initiatorCookie, 0, concatCookies, 0, COOKIE_LEN);
        System.arraycopy(responderCookie, 0, concatCookies, COOKIE_LEN, COOKIE_LEN);
        switch (ciphersuite.getAuthMethod()) {
            case RSA_Sig:
            case DSS_Sig: // For signatures: SKEYID = prf(Ni_b | Nr_b, g^xy)
                hmacKey = new SecretKeySpec(concatNonces, HmacIdentifier);
                prf.init(hmacKey);
                skeyid = prf.doFinal(this.ISAKMPSA.getDHSecret());
                break;

            case PKE:
            case RevPKE: // For public key encryption: SKEYID = prf(hash(Ni_b | Nr_b), CKY-I | CKY-R)
                // Cisco rather uses: SKEYID = prf(Ni_b | Nr_b, CKY-I | CKY-R)
                hmacKey = new SecretKeySpec(concatNonces, HmacIdentifier);
                prf.init(hmacKey);
                skeyid = prf.doFinal(concatCookies);
                break;

            case PSK: // For pre-shared keys: SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
                hmacKey = new SecretKeySpec(ltsecrets.getPreSharedKey(), HmacIdentifier);
                prf.init(hmacKey);
                skeyid = prf.doFinal(concatNonces);
                break;

            default:
                throw new UnsupportedOperationException("Unknown authMethod.");
        }
        SecretKeySpec skeyidspec = new SecretKeySpec(skeyid, HmacIdentifier);
        prf.init(skeyidspec);
        prf.update(this.ISAKMPSA.getDHSecret());
        prf.update(concatCookies);
        prf.update((byte) 0);
        skeyid_d = prf.doFinal();
        prf.update(skeyid_d);
        prf.update(this.ISAKMPSA.getDHSecret());
        prf.update(concatCookies);
        prf.update((byte) 1);
        skeyid_a = prf.doFinal();
        prf.update(skeyid_a);
        prf.update(this.ISAKMPSA.getDHSecret());
        prf.update(concatCookies);
        prf.update((byte) 2);
        skeyid_e = prf.doFinal();
        if (skeyid_e.length < ciphersuite.getCipher().getBlockSize()) {
            throw new UnsupportedOperationException("Not enough keying material. Additional PRF runs needed.");
        }
        ka = new byte[ciphersuite.getCipher().getBlockSize()];
        System.arraycopy(skeyid_e, 0, ka, 0, ka.length);
    }

    public byte[] getHASH_I() throws GeneralSecurityException {
        this.computeSecretKeys();
        Mac prf = Mac.getInstance("Hmac" + ciphersuite.getHash().toString());
        prf.init(new SecretKeySpec(this.getSKEYID(), "Hmac" + ciphersuite.getHash().toString()));
        prf.update(this.ISAKMPSA.getKeyExchangeData());
        prf.update(this.ISAKMPSA.getPeerKeyExchangeData());
        prf.update(this.initiatorCookie);
        prf.update(this.responderCookie);
        prf.update(this.ISAKMPSA.getSAOfferBody());
        return prf.doFinal(this.getIdentificationPayloadBody());
    }

    public byte[] getHASH_R() throws GeneralSecurityException {
        this.computeSecretKeys();
        Mac prf = Mac.getInstance("Hmac" + ciphersuite.getHash().toString());
        prf.init(new SecretKeySpec(this.getSKEYID(), "Hmac" + ciphersuite.getHash().toString()));
        prf.update(this.ISAKMPSA.getPeerKeyExchangeData());
        prf.update(this.ISAKMPSA.getKeyExchangeData());
        prf.update(this.getResponderCookie());
        prf.update(this.getInitiatorCookie());
        prf.update(this.ISAKMPSA.getSAOfferBody());
        return prf.doFinal(this.getPeerIdentificationPayloadBody());
    }

    public byte[] getHASH1(ISAKMPMessage msg) throws GeneralSecurityException {
        /* HASH(1) is the prf over the message id (M-ID) from the ISAKMP header 
         * concatenated with the entire message that follows the hash including 
         * all payload headers, but excluding any padding added for encryption.
         * Hash(1) = prf(SKEYID_a, M-ID | Message after HASH payload)
         */
        return getQuickModeHASH(msg, 1);
    }

    public byte[] getHASH2(ISAKMPMessage msg) throws GeneralSecurityException {
        /* HASH(2) is identical to HASH(1) except the initiator's nonce
         * -- Ni, minus the payload header -- is added after M-ID but before the
         * complete message. The addition of the nonce to HASH(2) is for a
         * liveliness proof.
         * Hash(2) = prf(SKEYID_a, M-ID | Ni_b | Message after HASH)
         */
        return getQuickModeHASH(msg, 2);
    }

    public byte[] getHASH3(ISAKMPMessage msg) throws GeneralSecurityException {
        /* HASH(3)-- for liveliness-- is the prf over the value zero represented
         * as a single octet, followed by a concatenation of the message id and
         * the two nonces-- the initiator's followed by the responder's-- minus
         * the payload header.
         * Hash(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
         */
        return getQuickModeHASH(msg, 3);
    }

    protected byte[] getQuickModeHASH(ISAKMPMessage msg, int index) throws GeneralSecurityException {
        this.computeSecretKeys();
        Mac prf = Mac.getInstance("Hmac" + ciphersuite.getHash().toString());
        prf.init(new SecretKeySpec(this.getSKEYID_a(), "Hmac" + ciphersuite.getHash().toString()));
        if (index == 3) {
            prf.update((byte) 0x0);
        }
        prf.update(msg.getMessageId());
        if (index == 2 || index == 3) {
            prf.update(getSA(msg.getMessageId()).getInitiatorNonce());
        }
        if (index == 3) {
            return prf.doFinal(getSA(msg.getMessageId()).getResponderNonce());
        }
        boolean encryptedFlag = msg.isEncryptedFlag();
        msg.setEncryptedFlag(false);
        byte[] bytes = msg.getBytes();
        msg.setEncryptedFlag(encryptedFlag);
        int offset = ISAKMPMessage.ISAKMP_HEADER_LEN;
        ISAKMPPayload firstPayload = msg.getPayloads().iterator().next();
        if (firstPayload.getType() == PayloadTypeEnum.Hash) {
            offset += firstPayload.getLength();
        }
        return prf.doFinal(Arrays.copyOfRange(bytes, offset, bytes.length));
    }

    public SASecrets getSA(byte[] msgID) {
        String msgIDStr = DatatypeHelper.byteArrayToHexDump(msgID);
        if (!SAs.containsKey(msgIDStr)) {
            SAs.put(msgIDStr, new SASecrets(ISAKMPSA.getDHGroup()));
        }
        return SAs.get(msgIDStr);
    }

    public byte[] getIV(byte[] msgID) throws GeneralSecurityException {
        String msgIDStr = DatatypeHelper.byteArrayToHexDump(msgID);
        if (!this.IVs.containsKey(msgIDStr)) {
            int blockSize = ciphersuite.getCipher().getBlockSize();
            try {
                MessageDigest digest = MessageDigest.getInstance(mapHashName(ciphersuite.getHash()));
                if (msgIDStr.equals("00000000")) {
                    digest.update(this.ISAKMPSA.getKeyExchangeData());
                    digest.update(this.ISAKMPSA.getPeerKeyExchangeData());
                } else {
                    digest.update(this.getIV(new byte[]{0x00, 0x00, 0x00, 0x00}));
                    digest.update(msgID);
                }
                byte[] hash = digest.digest();
                this.IVs.put(msgIDStr, Arrays.copyOf(hash, blockSize));
            } catch (NullPointerException ex) {
                return new byte[blockSize];
            }
        }
        return this.IVs.get(msgIDStr);
    }

    public void setIV(byte[] msgID, byte[] iv) {
        String msgIDStr = DatatypeHelper.byteArrayToHexDump(msgID);
        this.IVs.put(msgIDStr, iv);
    }

    public byte[] getIdentificationPayloadBody() {
        return identificationPayloadBody;
    }

    public void setIdentificationPayloadBody(byte[] identificationPayloadBody) {
        this.identificationPayloadBody = identificationPayloadBody;
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
