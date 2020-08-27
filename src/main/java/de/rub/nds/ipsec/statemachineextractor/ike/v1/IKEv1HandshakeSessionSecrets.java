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
import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEHandshakeSessionSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.HandshakeLongtermSecrets;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPMessage;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.CryptoHelper;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IKEv1HandshakeSessionSecrets extends GenericIKEHandshakeSessionSecrets {

    private byte[] skeyid, skeyid_d, skeyid_a, skeyid_e, ka, ke_i, ke_r;
    private byte[] identificationPayloadBody;
    private byte[] peerIdentificationPayloadBody;
    private final IKEv1Ciphersuite ciphersuite;

    public IKEv1HandshakeSessionSecrets(IKEv1Ciphersuite ciphersuite, HandshakeLongtermSecrets ltsecrets) {
        super(ciphersuite, ltsecrets);
        this.ciphersuite = ciphersuite;
        updateHandshakeSA();
    }

    public SecurityAssociationSecrets getHandshakeSA() {
        return HandshakeSA;
    }

    @Override
    public void generateDefaults() throws GeneralSecurityException {
        super.generateDefaults();
        this.HandshakeSA.setPeerKeyExchangeData(CryptoHelper.publicKey2Bytes(this.HandshakeSA.getDhKeyPair().getPublic()));
        this.HandshakeSA.computePeerPublicKey();
        this.HandshakeSA.generateDhKeyPair();
        this.HandshakeSA.computeDHSecret();
        computeSecretKeys();
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

    public byte[] getKe_i() {
        return ke_i;
    }

    public byte[] getKe_r() {
        return ke_r;
    }

    @Override
    public void computeSecretKeys() throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getHash().toString();
        Mac prf = Mac.getInstance(HmacIdentifier);
        SecretKeySpec hmacKey;
        byte[] initiatorNonce = this.HandshakeSA.getInitiatorNonce();
        if (initiatorNonce == null) {
            initiatorNonce = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        }
        byte[] responderNonce = this.HandshakeSA.getResponderNonce();
        byte[] concatNonces = new byte[initiatorNonce.length + responderNonce.length];
        System.arraycopy(initiatorNonce, 0, concatNonces, 0, initiatorNonce.length);
        System.arraycopy(responderNonce, 0, concatNonces, initiatorNonce.length, responderNonce.length);
        byte[] concatCookies = new byte[ISAKMPMessage.COOKIE_LEN * 2];
        System.arraycopy(initiatorCookie, 0, concatCookies, 0, ISAKMPMessage.COOKIE_LEN);
        System.arraycopy(responderCookie, 0, concatCookies, ISAKMPMessage.COOKIE_LEN, ISAKMPMessage.COOKIE_LEN);
        switch (ciphersuite.getAuthMethod()) {
            case RSA_Sig:
            case DSS_Sig: // For signatures: SKEYID = prf(Ni_b | Nr_b, g^xy)
                hmacKey = new SecretKeySpec(concatNonces, HmacIdentifier);
                prf.init(hmacKey);
                skeyid = prf.doFinal(this.HandshakeSA.getDHSecret());
                break;

            case PKE:
                // For public key encryption: SKEYID = prf(hash(Ni_b | Nr_b), CKY-I | CKY-R)
                // Cisco rather uses: SKEYID = prf(Ni_b | Nr_b, CKY-I | CKY-R)
                hmacKey = new SecretKeySpec(concatNonces, HmacIdentifier);
                prf.init(hmacKey);
                skeyid = prf.doFinal(concatCookies);
                break;

            case RevPKE:
                hmacKey = new SecretKeySpec(initiatorNonce, HmacIdentifier);
                prf.init(hmacKey);
                byte[] Ne_i = prf.doFinal(initiatorCookie);
                ke_i = new byte[ciphersuite.getCipher().getBlockSize()];
                System.arraycopy(Ne_i, 0, ke_i, 0, ke_i.length);
                hmacKey = new SecretKeySpec(responderNonce, HmacIdentifier);
                prf.init(hmacKey);
                byte[] Ne_r = prf.doFinal(responderCookie);
                ke_r = new byte[ciphersuite.getCipher().getBlockSize()];
                System.arraycopy(Ne_r, 0, ke_r, 0, ke_r.length);
                // For public key encryption: SKEYID = prf(hash(Ni_b | Nr_b), CKY-I | CKY-R)
                MessageDigest digest = MessageDigest.getInstance(mapHashName(ciphersuite.getHash()));
                hmacKey = new SecretKeySpec(digest.digest(concatNonces), HmacIdentifier);
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
        prf.update(this.HandshakeSA.getDHSecret());
        prf.update(concatCookies);
        prf.update((byte) 0);
        skeyid_d = prf.doFinal();
        prf.update(skeyid_d);
        prf.update(this.HandshakeSA.getDHSecret());
        prf.update(concatCookies);
        prf.update((byte) 1);
        skeyid_a = prf.doFinal();
        prf.update(skeyid_a);
        prf.update(this.HandshakeSA.getDHSecret());
        prf.update(concatCookies);
        prf.update((byte) 2);
        skeyid_e = prf.doFinal();
        if (skeyid_e.length < ciphersuite.getKeySize()) {
            throw new UnsupportedOperationException("Not enough keying material. Additional PRF runs needed.");
        }
        ka = new byte[ciphersuite.getKeySize()];
        System.arraycopy(skeyid_e, 0, ka, 0, ka.length);
    }

    public byte[] getHASH_I() throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getHash().toString();
        this.computeSecretKeys();
        Mac prf = Mac.getInstance(HmacIdentifier);
        prf.init(new SecretKeySpec(this.getSKEYID(), HmacIdentifier));
        prf.update(this.HandshakeSA.getKeyExchangeData());
        prf.update(this.HandshakeSA.getPeerKeyExchangeData());
        prf.update(this.initiatorCookie);
        prf.update(this.responderCookie);
        prf.update(this.HandshakeSA.getSAOfferBody());
        return prf.doFinal(this.getIdentificationPayloadBody());
    }

    public byte[] getHASH_R() throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getHash().toString();
        this.computeSecretKeys();
        Mac prf = Mac.getInstance(HmacIdentifier);
        prf.init(new SecretKeySpec(this.getSKEYID(), HmacIdentifier));
        prf.update(this.HandshakeSA.getPeerKeyExchangeData());
        prf.update(this.HandshakeSA.getKeyExchangeData());
        prf.update(this.getResponderCookie());
        prf.update(this.getInitiatorCookie());
        prf.update(this.HandshakeSA.getSAOfferBody());
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
        final String HmacIdentifier = "Hmac" + ciphersuite.getHash().toString();
        this.computeSecretKeys();
        Mac prf = Mac.getInstance(HmacIdentifier);
        prf.init(new SecretKeySpec(this.getSKEYID_a(), HmacIdentifier));
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
        int offset = ISAKMPMessage.IKE_MESSAGE_HEADER_LEN;
        ISAKMPPayload firstPayload = msg.getPayloads().iterator().next();
        if (firstPayload.getType() == IKEPayloadTypeEnum.Hash) {
            offset += firstPayload.getLength();
        }
        return prf.doFinal(Arrays.copyOfRange(bytes, offset, bytes.length));
    }

    @Override
    public void computeKeyMaterial(SecurityAssociationSecrets sas) throws GeneralSecurityException {
        final String HmacIdentifier = "Hmac" + ciphersuite.getHash().toString();
        this.computeSecretKeys();
        Mac prfIn = Mac.getInstance(HmacIdentifier);
        Mac prfOut = Mac.getInstance(HmacIdentifier);
        prfIn.init(new SecretKeySpec(this.getSKEYID_d(), HmacIdentifier));
        prfOut.init(new SecretKeySpec(this.getSKEYID_d(), HmacIdentifier));
        ByteArrayOutputStream inboundKeyMaterialOutputStream = new ByteArrayOutputStream((int) (KEY_MATERIAL_AMOUNT * 1.3));
        ByteArrayOutputStream outboundKeyMaterialOutputStream = new ByteArrayOutputStream((int) (KEY_MATERIAL_AMOUNT * 1.3));
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

    @Override
    public byte[] getIV(byte[] msgID) throws GeneralSecurityException {
        String msgIDStr = DatatypeHelper.byteArrayToHexDump(msgID);
        if (!this.IVs.containsKey(msgIDStr)) {
            int blockSize = ciphersuite.getCipherBlocksize();
            try {
                MessageDigest digest = MessageDigest.getInstance(mapHashName(ciphersuite.getHash()));
                if (msgIDStr.equals("00000000")) {
                    digest.update(this.HandshakeSA.getKeyExchangeData());
                    digest.update(this.HandshakeSA.getPeerKeyExchangeData());
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

    public byte[] getRPKEIV() throws GeneralSecurityException {
        String key = "RPKE";
        if (!this.IVs.containsKey(key)) {
            byte[] iv = new byte[ciphersuite.getCipher().getBlockSize()];
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
