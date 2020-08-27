/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.EncryptedISAKMPData;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPParsingException;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class EncryptedIKEv2Message extends IKEv2Message implements EncryptedISAKMPData {

    private final SecretKey ENCRsecretKey;
    private byte[] INTEGsecretKey;
    private IvParameterSpec IV;
    private Cipher cipherEnc, cipherDec;
    protected boolean isInSync = false;
    protected byte[] ciphertext;
    protected byte[] plaintext;
    private IKEPayloadTypeEnum nextPayload = IKEPayloadTypeEnum.EncryptedAndAuthenticated;
    private final EncryptionAlgorithmTransformEnum mode;
    private final IntegrityAlgorithmTransformEnum auth;
    private byte[] header = new byte[4];
    protected EncryptedPayload ENCRPayload = new EncryptedPayload();

    public EncryptedIKEv2Message(SecretKey ENCRsecretKey, EncryptionAlgorithmTransformEnum mode, byte[] IV, byte[] INTEGsecretKey, IntegrityAlgorithmTransformEnum auth) throws GeneralSecurityException {
        this.ENCRsecretKey = ENCRsecretKey;
        this.INTEGsecretKey = INTEGsecretKey;
        this.mode = mode;
        this.auth = auth;
        this.cipherDec = Cipher.getInstance(mode.cipherJCEName() + '/' + mode.modeOfOperationJCEName() + "/NoPadding");
        this.cipherEnc = Cipher.getInstance(mode.cipherJCEName() + '/' + mode.modeOfOperationJCEName() + "/NoPadding");
        this.IV = new IvParameterSpec(IV);
        this.ENCRPayload.setIV(IV);
    }

    @Override
    public void encrypt() throws GeneralSecurityException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.writeBytesOfPayloads(baos);
        cipherEnc.init(Cipher.ENCRYPT_MODE, ENCRsecretKey, IV);
        // TODO: Generate a null key if there is no good key material available
        this.plaintext = baos.toByteArray();
        //padding check
        if (this.plaintext.length % 16 != 0) {
            this.ENCRPayload.setPadLength((byte) (16 - ((this.plaintext.length % 16) + 1)));
            this.ENCRPayload.genRandomPadding();
            byte[] toEncrypt = new byte[plaintext.length + ENCRPayload.getPadLengthINT() + 1];
            System.arraycopy(plaintext, 0, toEncrypt, 0, plaintext.length);
            System.arraycopy(ENCRPayload.getPadding(), 0, toEncrypt, plaintext.length, ENCRPayload.getPadding().length);
            toEncrypt[plaintext.length + ENCRPayload.getPadLengthINT()] = ENCRPayload.getPadLength();
            this.ciphertext = cipherEnc.doFinal(toEncrypt);
            ENCRPayload.setEncryptedPayloads(this.ciphertext);
        } else {
            this.ciphertext = cipherEnc.doFinal(this.plaintext);
            this.ENCRPayload.setEncryptedPayloads(this.ciphertext);
        }
        this.isInSync = true;
    }

    @Override
    public void decrypt() throws GeneralSecurityException, GenericIKEParsingException {
        if (this.ciphertext.length == 0) {
            throw new IllegalStateException("No ciphertext set!");
        }
        cipherDec.init(Cipher.DECRYPT_MODE, ENCRsecretKey, IV);
        byte[] plaintextwithpadding = cipherDec.doFinal(this.ciphertext);
        byte[] plain = new byte[plaintextwithpadding.length - plaintextwithpadding[plaintextwithpadding.length - 1] - 1];
        System.arraycopy(plaintextwithpadding, 0, plain, 0, plain.length);
        this.plaintext = plain;
        byte[] plaintextwithheader = new byte[plaintext.length + 4 + this.ENCRPayload.getIV().length + this.ENCRPayload.getINTEGChecksumData().length + this.ciphertext.length];
        System.arraycopy(header, 0, plaintextwithheader, 0, header.length);
        System.arraycopy(this.ENCRPayload.getIV(), 0, plaintextwithheader, header.length, this.ENCRPayload.getIV().length);
        System.arraycopy(this.ciphertext, 0, plaintextwithheader, header.length + this.ENCRPayload.getIV().length, this.ciphertext.length);
        System.arraycopy(this.ENCRPayload.getINTEGChecksumData(), 0, plaintextwithheader, header.length + this.ENCRPayload.getIV().length + this.ciphertext.length, this.ENCRPayload.getINTEGChecksumData().length);
        System.arraycopy(plaintext, 0, plaintextwithheader, header.length + this.ENCRPayload.getIV().length + this.ciphertext.length + this.ENCRPayload.getINTEGChecksumData().length, plaintext.length);
        ByteArrayInputStream bais = new ByteArrayInputStream(plaintextwithheader);
        this.payloads.clear();
        IKEPayloadTypeEnum nextPayload = this.getNextPayload();
        while (nextPayload != IKEPayloadTypeEnum.NONE) {
            Class<? extends IKEv2Payload> payloadType = IKEv2Payload.getImplementingClass(nextPayload);
            IKEv2Payload payload;
            try {
                payload = payloadType.getConstructor((Class<?>[]) null).newInstance((Object[]) null);
            } catch (ReflectiveOperationException | SecurityException ex) {
                throw new ISAKMPParsingException(ex);
            }
            payload.fillFromStream(bais);
            nextPayload = payload.getNextPayload();
            this.addPayload(payload);
        }
        this.isInSync = true;
    }

    @Override
    public boolean isInSync() {
        return isInSync;
    }

    @Override
    public IKEPayloadTypeEnum getNextPayload() {
        if (this.isInSync) {
            this.nextPayload = super.getNextPayload();
        }
        return this.nextPayload;
    }

    public void setNextPayload(IKEPayloadTypeEnum nextPayload) {
        if (this.nextPayload != nextPayload) {
            this.isInSync = false;
        }
        this.nextPayload = nextPayload;
    }

    public byte[] getPlaintext() {
        if (!isInSync) {
            throw new IllegalStateException("Plaintext not up to date. Run encrypt() or decrypt() first!");
        }
        return plaintext.clone();
    }

    @Override
    public byte[] getCiphertext() {
        if (!isInSync) {
            throw new IllegalStateException("Ciphertext not up to date. Run encrypt() first!");
        }
        return ciphertext.clone();
    }

    public void setCiphertext(ByteArrayInputStream bais) {
        this.ciphertext = new byte[bais.available() - 4 - this.ENCRPayload.getIV().length - 12];
        bais.read(this.header, 0, this.header.length);
        byte[] buffer = new byte[this.ENCRPayload.getIV().length];
        bais.read(buffer, 0, buffer.length);
        this.ENCRPayload.setIV(buffer);
        this.IV = new IvParameterSpec(this.ENCRPayload.getIV());
        bais.read(this.ciphertext, 0, this.ciphertext.length);
        byte[] buffer1 = new byte[12];
        bais.read(buffer1, 0, buffer1.length);
        this.ENCRPayload.setINTEGChecksumData(buffer1);
        this.ENCRPayload.setEncryptedPayloads(this.ciphertext);
        this.isInSync = false;
    }

    @Override
    public int getLength() {
        if (!this.isInSync) {
            try {
                this.encrypt();
            } catch (GeneralSecurityException ex) {
                throw new RuntimeException(ex);
            }
        }
        return HEADER_LEN + this.ENCRPayload.getLength();
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        if (!this.isInSync) {
            this.computeINTEGChecksumData();
        }
        super.writeBytes(baos);
    }

    public void computeINTEGChecksumData() {
        if (this.ciphertext == null) {
            try {
                this.encrypt();
            } catch (GeneralSecurityException ex) {
                throw new RuntimeException(ex);
            }
        }
        addPayload(this.ENCRPayload);
        final String HmacIdentifier = "Hmac" + this.auth.toString();
        try {
            Mac checksumData = Mac.getInstance(HmacIdentifier);
            SecretKeySpec hmacKey = new SecretKeySpec(this.INTEGsecretKey, HmacIdentifier);
            checksumData.init(hmacKey);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            super.writeBytes(baos);
            byte[] predata = checksumData.doFinal(baos.toByteArray());
            byte[] data = new byte[12]; //dymanic legth!!!!
            System.arraycopy(predata, 0, data, 0, data.length);
            this.ENCRPayload.setINTEGChecksumData(data);
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
        this.isInSync = true;
    }

    public static EncryptedIKEv2Message fromPlainMessage(IKEv2Message msg, SecretKey ENCRsecretKey, EncryptionAlgorithmTransformEnum mode, byte[] IV, byte[] INTEGsecretKey, IntegrityAlgorithmTransformEnum auth) throws GeneralSecurityException {
        EncryptedIKEv2Message enc = new EncryptedIKEv2Message(ENCRsecretKey, mode, IV, INTEGsecretKey, auth);
        enc.setInitiatorCookie(msg.getInitiatorCookie());
        enc.setResponderCookie(msg.getResponderCookie());
        enc.setVersion(msg.getVersion());
        enc.setMessageId(msg.getMessageId());
        enc.setExchangeType(msg.getExchangeType());
        enc.setInitiatorFlag(msg.isInitiatorFlag());
        enc.setVersionFlag(msg.isVersionFlag());
        enc.setResponseFlag(msg.isResponseFlag());
        msg.getPayloads().forEach((p) -> {
            enc.addPayload(p);
        });
        return enc;
    }

}
