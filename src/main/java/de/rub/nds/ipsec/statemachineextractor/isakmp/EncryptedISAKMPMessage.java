/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.CipherAttributeEnum;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class EncryptedISAKMPMessage extends ISAKMPMessage implements EncryptedISAKMPData {

    private final SecretKey secretKey;
    private final IvParameterSpec IV;
    private byte[] nextIV = new byte[0];
    private final Cipher cipherEnc, cipherDec;
    protected boolean isInSync = false;
    protected byte[] ciphertext = new byte[0];
    protected byte[] plaintext;
    private PayloadTypeEnum nextPayload = PayloadTypeEnum.NONE;

    public EncryptedISAKMPMessage(SecretKey secretKey, CipherAttributeEnum mode, byte[] IV) throws GeneralSecurityException {
        this.secretKey = secretKey;
        this.cipherDec = Cipher.getInstance(mode.cipherJCEName() + '/' + mode.modeOfOperationJCEName() + "/NoPadding");
        this.cipherEnc = Cipher.getInstance(mode.cipherJCEName() + '/' + mode.modeOfOperationJCEName() + "/ZeroBytePadding");
        this.IV = new IvParameterSpec(IV);
        this.setEncryptedFlag(true);
    }

    @Override
    public void encrypt() throws GeneralSecurityException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.writeBytesOfPayloads(baos);
        try {
            cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, IV);
        } catch (InvalidKeyException ex) {
            // Generate a random key if there is no good key material available
            KeyGenerator kg = KeyGenerator.getInstance(cipherEnc.getParameters().getAlgorithm());
            SecretKey randomKey = kg.generateKey();
            cipherEnc.init(Cipher.ENCRYPT_MODE, randomKey, IV);
        }
        this.plaintext = baos.toByteArray();
        this.ciphertext = cipherEnc.doFinal(this.plaintext);
        this.nextIV = Arrays.copyOfRange(this.ciphertext, this.ciphertext.length - cipherEnc.getBlockSize(), this.ciphertext.length);
        this.isInSync = true;
    }

    @Override
    public void decrypt() throws GeneralSecurityException, ISAKMPParsingException {
        if (this.ciphertext.length == 0) {
            throw new IllegalStateException("No ciphertext set!");
        }
        cipherDec.init(Cipher.DECRYPT_MODE, secretKey, IV);
        this.plaintext = cipherDec.doFinal(this.ciphertext);
        ByteArrayInputStream bais = new ByteArrayInputStream(this.plaintext);
        this.payloads.clear();
        PayloadTypeEnum nextPayload = this.getNextPayload();
        while (nextPayload != PayloadTypeEnum.NONE) {
            Class<? extends ISAKMPPayload> payloadType = ISAKMPPayload.getImplementingClass(nextPayload);
            ISAKMPPayload payload;
            try {
                payload = payloadType.getConstructor((Class<?>[]) null).newInstance((Object[]) null);
            } catch (ReflectiveOperationException | SecurityException ex) {
                throw new ISAKMPParsingException(ex);
            }
            payload.fillFromStream(bais);
            nextPayload = payload.getNextPayload();
            this.addPayload(payload);
        }
        this.nextIV = Arrays.copyOfRange(this.ciphertext, this.ciphertext.length - cipherDec.getBlockSize(), this.ciphertext.length);
        this.plaintext = Arrays.copyOf(this.plaintext, super.getLength() - ISAKMP_HEADER_LEN); // remove padding
        this.isInSync = true;
    }

    public byte[] getNextIV() {
        return nextIV.clone();
    }

    @Override
    public boolean isInSync() {
        return isInSync;
    }

    @Override
    public PayloadTypeEnum getNextPayload() {
        if (this.isInSync) {
            this.nextPayload = super.getNextPayload();
        }
        return this.nextPayload;
    }

    public void setNextPayload(PayloadTypeEnum nextPayload) {
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
        this.ciphertext = new byte[bais.available()];
        bais.read(this.ciphertext, 0, this.ciphertext.length);
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
        return ISAKMP_HEADER_LEN + this.ciphertext.length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        if (!this.isEncryptedFlag()) {
            super.writeBytes(baos);
            return;
        }
        this.nextPayload = super.getNextPayload();
        writeBytesWithoutPayloads(baos);
        try {
            this.encrypt();
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
        baos.write(this.ciphertext, 0, this.ciphertext.length);
    }

    public static EncryptedISAKMPMessage fromPlainMessage(ISAKMPMessage msg, SecretKey secretKey, CipherAttributeEnum mode, byte[] IV) throws GeneralSecurityException {
        EncryptedISAKMPMessage enc = new EncryptedISAKMPMessage(secretKey, mode, IV);
        enc.setInitiatorCookie(msg.getInitiatorCookie());
        enc.setResponderCookie(msg.getResponderCookie());
        enc.setVersion(msg.getVersion());
        enc.setExchangeType(msg.getExchangeType());
        enc.setEncryptedFlag(true);
        enc.setCommitFlag(msg.isCommitFlag());
        enc.setAuthenticationOnlyFlag(msg.isAuthenticationOnlyFlag());
        enc.setMessageId(msg.getMessageId());
        msg.getPayloads().forEach((p) -> {
            enc.addPayload(p);
        });
        return enc;
    }

}
