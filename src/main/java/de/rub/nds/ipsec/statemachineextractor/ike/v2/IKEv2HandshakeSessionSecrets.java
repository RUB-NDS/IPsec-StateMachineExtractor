/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2;

import de.rub.nds.ipsec.statemachineextractor.ike.HandshakeLongtermSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEHandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.SecurityAssociationSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures.IKEv2Message;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv2HandshakeSessionSecrets extends GenericIKEHandshakeSessionSecrets {

    private byte[] SKEYSEED, SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr, pad;
    private byte[] IDi, IDr;
    private byte[] octets, message;
    private final IKEv2Ciphersuite ciphersuite;
    protected SecurityAssociationSecrets IPsecSA;

    public IKEv2HandshakeSessionSecrets(IKEv2Ciphersuite ciphersuite, HandshakeLongtermSecrets ltsecrets) {
        super(ciphersuite, ltsecrets);
        this.ciphersuite = ciphersuite;
        updateHandshakeSA();
        this.IPsecSA = getSA(new byte[]{0, 0, 0, 1});
    }

    public SecurityAssociationSecrets getIPsecSA() {
        return IPsecSA;
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
        return SK_pr;
    }

    public byte[] getSKeyseed() {
        return SKEYSEED;
    }

    @Override
    public void computeSecretKeys() throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getPrf().toString();
        Mac prf = Mac.getInstance(HmacIdentifier);
        SecretKeySpec hmacKey;
        byte[] concatNonces = getConcatNonces();
        byte[] concatCookies = Arrays.copyOf(initiatorCookie, IKEv2Message.COOKIE_LEN * 2);
        System.arraycopy(responderCookie, 0, concatCookies, IKEv2Message.COOKIE_LEN, IKEv2Message.COOKIE_LEN);
        hmacKey = new SecretKeySpec(concatNonces, HmacIdentifier);
        prf.init(hmacKey);
        SKEYSEED = prf.doFinal(this.HandshakeSA.getDHSecret());

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
            SK_ei = Arrays.copyOf(SK_ei_pre, ciphersuite.getKeySize());
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

    private byte[] getConcatNonces() {
        byte[] initiatorNonce = this.HandshakeSA.getInitiatorNonce();
        if (initiatorNonce == null) {
            initiatorNonce = new byte[8];
        }
        byte[] responderNonce = this.HandshakeSA.getResponderNonce();
        byte[] concatNonces = Arrays.copyOf(initiatorNonce, initiatorNonce.length + responderNonce.length);
        System.arraycopy(responderNonce, 0, concatNonces, initiatorNonce.length, responderNonce.length);
        return concatNonces;
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
        if (this.SK_pi == null || this.SK_pi.length == 0) {
            this.computeSecretKeys();
        }
        hmacKey = new SecretKeySpec(this.SK_pi, HmacIdentifier);
        prf.init(hmacKey);
        byte[] MACedIDForI = prf.doFinal(this.IDi);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            if (message != null) {
                baos.write(message);
            }
            baos.write(this.HandshakeSA.getResponderNonce());
            baos.write(MACedIDForI);
        } catch (IOException ex) {
            throw new RuntimeException("If your JRE's implementation of ByteArrayOutputStream is sane, then it's impossible that this exception is thrown", ex);
        }
        octets = baos.toByteArray();
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

    @Override
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

    @Override
    public void computeKeyMaterial(SecurityAssociationSecrets ipsec_sas) throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getPrf().toString();
        this.computeSecretKeys();
        Mac prf = Mac.getInstance(HmacIdentifier);
        prf.init(new SecretKeySpec(this.getSKd(), HmacIdentifier));
        ByteArrayOutputStream keyMaterialOutputStream = new ByteArrayOutputStream(2 * KEY_MATERIAL_AMOUNT);
        byte[] lastBlock = new byte[0];
        byte[] dhsecret = new byte[0];
        if (ipsec_sas.getDHSecret() != null) {
            dhsecret = ipsec_sas.getDHSecret();
        }
        byte[] concatNonces = getConcatNonces();
        byte counter = 1;
        while (keyMaterialOutputStream.size() < 2 * KEY_MATERIAL_AMOUNT) {
            prf.update(lastBlock);
            prf.update(dhsecret);
            prf.update(concatNonces);
            prf.update(counter++);
            lastBlock = prf.doFinal();
            keyMaterialOutputStream.write(lastBlock, 0, lastBlock.length);
        }
        ByteArrayInputStream bais = new ByteArrayInputStream(keyMaterialOutputStream.toByteArray());
        // Use same stream twice
        ipsec_sas.setOutboundKeyMaterial(bais);
        ipsec_sas.setInboundKeyMaterial(bais);
    }
}
