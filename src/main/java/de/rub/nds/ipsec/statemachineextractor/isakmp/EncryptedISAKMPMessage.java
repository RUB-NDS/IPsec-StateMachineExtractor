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
import java.util.Arrays;
import javax.crypto.Cipher;
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
    private final Cipher cipher;
    protected boolean isInSync = false;
    protected byte[] ciphertext = new byte[0];
    private PayloadTypeEnum nextPayload = PayloadTypeEnum.NONE;

    public EncryptedISAKMPMessage(SecretKey secretKey, CipherAttributeEnum mode, byte[] IV) throws GeneralSecurityException {
        this.secretKey = secretKey;
        this.cipher = Cipher.getInstance(mode.cipherJCEName() + '/' + mode.modeOfOperationJCEName() + "/ZeroBytePadding");
        this.IV = new IvParameterSpec(IV);
        this.setEncryptedFlag(true);
    }

    @Override
    public void encrypt() throws GeneralSecurityException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.writeBytesOfPayloads(baos);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IV);
        this.ciphertext = cipher.doFinal(baos.toByteArray());
        this.nextIV = Arrays.copyOfRange(this.ciphertext, this.ciphertext.length - cipher.getBlockSize(), this.ciphertext.length);
        this.isInSync = true;
    }

    @Override
    public void decrypt() throws GeneralSecurityException, ISAKMPParsingException {
        if (this.ciphertext.length == 0) {
            throw new IllegalStateException("No ciphertext set!");
        }
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IV);
        byte[] plaintext = cipher.doFinal(this.ciphertext);
        ByteArrayInputStream bais = new ByteArrayInputStream(plaintext);
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
        this.nextIV = Arrays.copyOfRange(this.ciphertext, this.ciphertext.length - cipher.getBlockSize(), this.ciphertext.length);
        this.isInSync = true;
    }

    public byte[] getNextIV() {
        return nextIV.clone();
    }

    @Override
    public boolean isIsInSync() {
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
        try {
            this.encrypt();
            return ISAKMP_HEADER_LEN + this.ciphertext.length;
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
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

//    byte[] addRFC2409Padding(byte[] in) {
//        int byteLength = ((int) Math.ceil((float) in.length / cipher.getBlockSize())) * cipher.getBlockSize();
//        if (in.length % cipher.getBlockSize() == 0) {
//            byteLength += cipher.getBlockSize();
//        }
//        byte[] out = new byte[byteLength];
//        System.arraycopy(in, 0, out, 0, in.length);
//        out[out.length - 1] = (byte) (out.length - in.length - 1);
//        return out;
//    }
//
//    byte[] removeRFC2409Padding(byte[] in) throws BadPaddingException, IllegalBlockSizeException {
//        if (in.length % cipher.getBlockSize() != 0) {
//            throw new IllegalBlockSizeException();
//        }
//        int padLength = in[in.length - 1] + 1;
//        if (padLength > cipher.getBlockSize() || padLength <= 0) {
//            throw new BadPaddingException();
//        }
//        int i = padLength;
//        while (i > 1) {
//            if (in[in.length - i] != 0) {
//                throw new BadPaddingException();
//            }
//            i--;
//        }
//        byte[] out = new byte[in.length - padLength];
//        System.arraycopy(in, 0, out, 0, in.length - padLength);
//        return out;
//    }
}
