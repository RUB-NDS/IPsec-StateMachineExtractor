/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2;

import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.ISAKMPMessagev2;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2HandshakeSessionSecrets {

    protected static final int KEY_MATERIAL_AMOUNT = 512;

    private boolean isInitiatorCookieChosen = false;
    private byte[] initiatorCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] responderCookie = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private final Map<String, byte[]> IVs = new HashMap<>();
    private final Map<String, SecurityAssociationSecrets> SAs = new HashMap<>();
    private byte[] SKEYSEED, SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr, pad;
    private byte[] IDi, IDr;
    private byte[] peerIdentificationPayloadBody;
    private byte[] mostRecentMessageID;
    private byte[] octets, message;
    private SecurityAssociationSecrets ISAKMPSA;

    private final IKEv2Ciphersuite ciphersuite;
    private final IKEv2HandshakeLongtermSecrets ltsecrets;

    public IKEv2HandshakeSessionSecrets(IKEv2Ciphersuite ciphersuite, IKEv2HandshakeLongtermSecrets ltsecrets) {
        this.ciphersuite = ciphersuite;
        this.ltsecrets = ltsecrets;
        updateISAKMPSA();
    }

    public final void updateISAKMPSA() {
        if (this.ISAKMPSA == null || this.ciphersuite.getDhGroup() != this.ISAKMPSA.getDHGroup()) {
            this.ISAKMPSA = new SecurityAssociationSecrets(this.ciphersuite.getDhGroup());
            this.SAs.put("00000000", this.ISAKMPSA);
        }
    }

    public SecurityAssociationSecrets getISAKMPSA() {
        return ISAKMPSA;
    }

    public void generateDefaults() throws GeneralSecurityException {
        updateISAKMPSA();
        this.ISAKMPSA.generateDhKeyPair();
        //this.ISAKMPSA.setPeerKeyExchangeData(CryptoHelper.publicKey2Bytes(this.ISAKMPSA.getDhKeyPair().getPublic()));
        //this.ISAKMPSA.computePeerPublicKey();
        //this.ISAKMPSA.generateDhKeyPair();
        //this.ISAKMPSA.computeDHSecret();
        //computeSecretKeys();
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

    public byte[] getSKai() {
        return SK_ai;
    }

    public byte[] getSKar() {
        return SK_ar;
    }

    public byte[] getSKd() {
        return SK_d;
    }

    public byte[] getSKei() {
        return SK_ei;
    }

    public byte[] getSKer() {
        return SK_er;
    }

    public byte[] getSKpi() {
        return SK_pi;
    }

    public byte[] getSKpr() {
        return SK_pi;
    }

    public byte[] getSKeyseed() {
        return SKEYSEED;
    }

    public void computeSecretKeys() throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getPrf().toString();
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
        byte[] concatCookies = new byte[ISAKMPMessagev2.COOKIE_LEN * 2];
        System.arraycopy(initiatorCookie, 0, concatCookies, 0, ISAKMPMessagev2.COOKIE_LEN);
        System.arraycopy(responderCookie, 0, concatCookies, ISAKMPMessagev2.COOKIE_LEN, ISAKMPMessagev2.COOKIE_LEN);
        hmacKey = new SecretKeySpec(concatNonces, HmacIdentifier);
        prf.init(hmacKey);
        SKEYSEED = prf.doFinal(this.ISAKMPSA.getDHSecret());

        SecretKeySpec skeyd = new SecretKeySpec(SKEYSEED, HmacIdentifier);
        prf.init(skeyd);

        prf.update(concatNonces);
        prf.update(concatCookies);
        prf.update((byte) 1);
        SK_d = prf.doFinal();

        prf.update(SK_d);
        prf.update(concatNonces);
        prf.update(concatCookies);
        prf.update((byte) 2);
        SK_ai = prf.doFinal();

        prf.update(SK_ai);
        prf.update(concatNonces);
        prf.update(concatCookies);
        prf.update((byte) 3);
        SK_ar = prf.doFinal();

        prf.update(SK_ar);
        prf.update(concatNonces);
        prf.update(concatCookies);
        prf.update((byte) 4);
        byte[] SK_ei_pre = prf.doFinal();
        if (SK_ei_pre.length < ciphersuite.getKeySize()) {
            throw new UnsupportedOperationException("Not enough keying material. Additional PRF runs needed.");
        } else if (SK_ei_pre.length > ciphersuite.getKeySize()) {
            SK_ei = new byte[ciphersuite.getKeySize()];
            System.arraycopy(SK_ei_pre, 0, SK_ei, 0, SK_ei.length);
            pad = new byte[SK_ei_pre.length - SK_ei.length];
            System.arraycopy(SK_ei_pre, SK_ei.length, pad, 0, SK_ei_pre.length - SK_ei.length);
        } else {
            SK_ei = SK_ei_pre;
        }

        prf.update(SK_ei_pre);
        prf.update(concatNonces);
        prf.update(concatCookies);
        prf.update((byte) 5);
        byte[] SK_er_pre = prf.doFinal();
        if (SK_er_pre.length < ciphersuite.getKeySize()) {
            throw new UnsupportedOperationException("Not enough keying material. Additional PRF runs needed.");
        } else if (SK_er_pre.length > ciphersuite.getKeySize()) {
            int len = pad.length;
            SK_er = new byte[ciphersuite.getKeySize()];
            System.arraycopy(pad, 0, SK_er, 0, len);
            System.arraycopy(SK_er_pre, 0, SK_er, len, SK_er.length - len);
            pad = new byte[SK_er_pre.length - (SK_er.length - len)];
            System.arraycopy(SK_er_pre, SK_er.length - len, pad, 0, pad.length);
        } else {
            SK_er = SK_er_pre;
        }

        prf.update(SK_er_pre);
        prf.update(concatNonces);
        prf.update(concatCookies);
        prf.update((byte) 6);
        byte[] SK_pi_pre = prf.doFinal();
        if (pad.length > 0) {
            int len = pad.length;
            SK_pi = new byte[SK_d.length];
            System.arraycopy(pad, 0, SK_pi, 0, len);
            System.arraycopy(SK_pi_pre, 0, SK_pi, len, SK_pi.length - len);
            pad = new byte[SK_pi_pre.length - (SK_pi.length - len)];
            System.arraycopy(SK_pi_pre, SK_pi.length - len, pad, 0, pad.length);
        } else {
            SK_pi = SK_pi_pre;
        }

        prf.update(SK_pi_pre);
        prf.update(concatNonces);
        prf.update(concatCookies);
        prf.update((byte) 7);
        byte[] SK_pr_pre = prf.doFinal();
        if (pad.length > 0) {
            int len = pad.length;
            SK_pr = new byte[SK_d.length];
            System.arraycopy(pad, 0, SK_pr, 0, len);
            System.arraycopy(SK_pr_pre, 0, SK_pr, len, SK_pr.length - len);
            pad = new byte[SK_pr_pre.length - (SK_pr.length - len)];
            System.arraycopy(SK_pr_pre, SK_pr.length - len, pad, 0, pad.length);
        } else {
            SK_pr = SK_pr_pre;
        }
    }

    public byte[] getMessage() {
        return message.clone();
    }

    public void setMessage(byte[] message) {
        this.message = message;
    }

    public byte[] getOctets() {
        return octets.clone();
    }

    public void computeOctets() throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getPrf().toString();
        Mac prf = Mac.getInstance(HmacIdentifier);
        SecretKeySpec hmacKey;
        hmacKey = new SecretKeySpec(this.SK_pi, HmacIdentifier);
        prf.init(hmacKey);
        byte[] MACedIDForI = prf.doFinal(this.IDi);
        byte[] RealMessage1 = getMessage();
        byte[] NonceRData = this.ISAKMPSA.getResponderNonce();
        octets = new byte[MACedIDForI.length + RealMessage1.length + NonceRData.length];
        System.arraycopy(RealMessage1, 0, octets, 0, RealMessage1.length);
        System.arraycopy(NonceRData, 0, octets, RealMessage1.length, NonceRData.length);
        System.arraycopy(MACedIDForI, 0, octets, RealMessage1.length + NonceRData.length, MACedIDForI.length);
    }

    public byte[] getIDi() {
        return IDi.clone();
    }

    public void setIDi(byte[] IDi) {
        this.IDi = IDi;
    }

    public byte[] getIDr() {
        return IDr.clone();
    }

    public void setIDr(byte[] IDr) {
        this.IDr = IDr;
    }

    public byte[] computeAUTH() throws GeneralSecurityException {
        //only PSK
        final String HmacIdentifier = "Hmac" + ciphersuite.getPrf().toString();
        Mac prf = Mac.getInstance(HmacIdentifier);
        SecretKeySpec hmacKey;
        hmacKey = new SecretKeySpec(ltsecrets.getPreSharedKey(), HmacIdentifier);
        prf.init(hmacKey);
        byte[] innerprf = prf.doFinal("Key Pad for IKEv2".getBytes());
        SecretKeySpec auth = new SecretKeySpec(innerprf, HmacIdentifier);
        prf.init(auth);
        return prf.doFinal(this.octets);
    }


    /*
    public byte[] getPrf_I() throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getPrf().toString();
        this.computeSecretKeys();
        Mac prf = Mac.getInstance(HmacIdentifier);
        prf.init(new SecretKeySpec(this.getSKEYID(), HmacIdentifier));
        prf.update(this.ISAKMPSA.getKeyExchangeData());
        prf.update(this.ISAKMPSA.getPeerKeyExchangeData());
        prf.update(this.initiatorCookie);
        prf.update(this.responderCookie);
        prf.update(this.ISAKMPSA.getSAOfferBody());
        return prf.doFinal(this.getIdentificationPayloadBody());
    }

    public byte[] getPrf_R() throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getPrf().toString();
        this.computeSecretKeys();
        Mac prf = Mac.getInstance(HmacIdentifier);
        prf.init(new SecretKeySpec(this.getSKEYID(), HmacIdentifier));
        prf.update(this.ISAKMPSA.getPeerKeyExchangeData());
        prf.update(this.ISAKMPSA.getKeyExchangeData());
        prf.update(this.getResponderCookie());
        prf.update(this.getInitiatorCookie());
        prf.update(this.ISAKMPSA.getSAOfferBody());
        return prf.doFinal(this.getPeerIdentificationPayloadBody());
    }

    public byte[] getPrf1(ISAKMPMessagev2 msg) throws GeneralSecurityException {
        return getQuickModeHASH(msg, 1);
    }

    public byte[] getPrf2(ISAKMPMessagev2 msg) throws GeneralSecurityException {
        return getQuickModeHASH(msg, 2);
    }

    public byte[] getPrf3(ISAKMPMessagev2 msg) throws GeneralSecurityException {
        return getQuickModeHASH(msg, 3);
    }
    public void computeKeyMaterial(SecurityAssociationSecrets sas) throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getPrf().toString();
        this.computeSecretKeys();
        Mac prfIn = Mac.getInstance(HmacIdentifier);
        Mac prfOut = Mac.getInstance(HmacIdentifier);
        prfIn.init(new SecretKeySpec(this.getSKEYID_d(), HmacIdentifier));
        prfOut.init(new SecretKeySpec(this.getSKEYID_d(), HmacIdentifier));
        ByteArrayOutputStream inboundKeyMaterialOutputStream = new ByteArrayOutputStream((int)(KEY_MATERIAL_AMOUNT * 1.3));
        ByteArrayOutputStream outboundKeyMaterialOutputStream = new ByteArrayOutputStream((int)(KEY_MATERIAL_AMOUNT * 1.3));                
        byte[] lastBlockIn = new byte[0], lastBlockOut = new byte[0];
        while (inboundKeyMaterialOutputStream.size() < KEY_MATERIAL_AMOUNT || outboundKeyMaterialOutputStream.size() < KEY_MATERIAL_AMOUNT) {
            prfIn.update(lastBlockIn);
            prfOut.update(lastBlockOut);
            if (sas.getDHSecret() != null) {
                prfIn.update(sas.getDHSecret());
                prfOut.update(sas.getDHSecret());
            }
            prfIn.update(sas.getProtocol().getValue());
            prfOut.update(sas.getProtocol().getValue());
            prfIn.update(sas.getInboundSpi());
            prfOut.update(sas.getOutboundSpi());
            prfIn.update(sas.getInitiatorNonce());
            prfOut.update(sas.getInitiatorNonce());
            prfIn.update(sas.getResponderNonce());
            prfOut.update(sas.getResponderNonce());
            lastBlockIn = prfIn.doFinal();
            lastBlockOut = prfOut.doFinal();
            inboundKeyMaterialOutputStream.write(lastBlockIn, 0, lastBlockIn.length);
            outboundKeyMaterialOutputStream.write(lastBlockOut, 0, lastBlockOut.length);
        }
        sas.setInboundKeyMaterial(inboundKeyMaterialOutputStream.toByteArray());
        sas.setOutboundKeyMaterial(outboundKeyMaterialOutputStream.toByteArray());
    }
     */
    public SecurityAssociationSecrets getSA(byte[] msgID) {
        String msgIDStr = DatatypeHelper.byteArrayToHexDump(msgID);
        if (!SAs.containsKey(msgIDStr)) {
            SAs.put(msgIDStr, new SecurityAssociationSecrets(ISAKMPSA.getDHGroup())); //TODO: Set group based on Security Association payload
        }
        return SAs.get(msgIDStr);
    }

    public byte[] getIV(byte[] msgID) throws GeneralSecurityException {
        String msgIDStr = DatatypeHelper.byteArrayToHexDump(msgID);
        if (!this.IVs.containsKey(msgIDStr)) {
            int blockSize = 16; //hardcoded need change to blocksize attriubute
            SecureRandom random = new SecureRandom();
            byte[] IV = new byte[blockSize];
            random.nextBytes(IV);
            setIV(msgID, IV);
        }
        return this.IVs.get(msgIDStr);
    }

    public void setIV(byte[] msgID, byte[] iv) {
        String msgIDStr = DatatypeHelper.byteArrayToHexDump(msgID);
        this.IVs.put(msgIDStr, iv);
    }

    public byte[] getRPKEIV() throws GeneralSecurityException {
        String key = "RPKE";
        if (!this.IVs.containsKey(key)) {
            byte[] iv = new byte[16];
            this.IVs.put(key, iv);
        }
        return this.IVs.get(key);
    }

    public void setRPKEIV(byte[] iv) {
        /*
         * RFC2409 states the following: "The IV for encrypting the first
         * payload following the nonce is set to 0 (zero). The IV for subsequent
         * payloads encrypted with the ephemeral symmetric cipher key, Ke_i, is
         * the last ciphertext block of the previous payload."
         * 
         * Huawei however ignores the second sentence and always uses the
         * zero-IV. Since Huawei is the only known implementation of RevPKE, we
         * simply disable storing the new IV.
         */
        //this.IVs.put("RPKE", iv);
    }

    public byte[] getPeerIdentificationPayloadBody() {
        return peerIdentificationPayloadBody;
    }

    public void setPeerIdentificationPayloadBody(byte[] peerIdentificationPayloadBody) {
        this.peerIdentificationPayloadBody = peerIdentificationPayloadBody;
    }

    private static String mapHashName(ProtocolTransformIDEnum hash) {
        switch (hash) {
            case IKEV2_INTEG_HMAC_SHA1_96:
                return "SHA-1";
            default:
                return hash.toString();
        }
    }
}
