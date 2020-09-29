/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SymmetricallyEncryptedISAKMPPayload extends ISAKMPPayload implements EncryptedISAKMPPayload {

    private final SecretKeySpec ke;
    protected boolean isInSync;
    protected byte[] encryptedBody = new byte[0];
    private final ISAKMPPayload underlyingPayload;
    private final Cipher cipher;
    private IvParameterSpec IV;
    private byte[] nextIV = new byte[0];

    public SymmetricallyEncryptedISAKMPPayload(ISAKMPPayload payload, IKEv1Ciphersuite ciphersuite, SecretKeySpec ke) throws GeneralSecurityException {
        this(payload, ciphersuite, ke, null);
    }

    public SymmetricallyEncryptedISAKMPPayload(ISAKMPPayload payload, IKEv1Ciphersuite ciphersuite, SecretKeySpec ke, byte[] iv) throws GeneralSecurityException {
        super(payload.getType());
        this.underlyingPayload = payload;
        if (!ke.getAlgorithm().equals(ciphersuite.getCipher().cipherJCEName())) {
            throw new IllegalArgumentException("Encryption algorithm does not match the ciphersuite!");
        }
        this.ke = ke;
        this.isInSync = false;
        this.cipher = Cipher.getInstance(ciphersuite.getCipher().cipherJCEName() + '/' + ciphersuite.getCipher().modeOfOperationJCEName() + "/NoPadding");
        if (!ciphersuite.getCipher().isFixedKeySize() && (ke.getEncoded().length != ciphersuite.getKeylength().getKeySize())) {
            throw new IllegalArgumentException("Key length does not match the ciphersuite!");
        }
        if (iv == null) {
            iv = new byte[this.cipher.getBlockSize()];
        }
        this.IV = new IvParameterSpec(iv);
    }

    protected byte[] addRFC2409Padding(byte[] in) {
        int byteLength = ((int) Math.ceil((float) in.length / cipher.getBlockSize())) * cipher.getBlockSize();
        if (in.length % cipher.getBlockSize() == 0) {
            byteLength += cipher.getBlockSize();
        }
        byte[] out = Arrays.copyOf(in, byteLength);
        out[out.length - 1] = (byte) (out.length - in.length - 1);
        return out;
    }

    protected byte[] removeRFC2409Padding(byte[] in) throws BadPaddingException, IllegalBlockSizeException {
        if (in.length % cipher.getBlockSize() != 0) {
            throw new IllegalBlockSizeException();
        }
        int padLength = in[in.length - 1] + 1;
        if (padLength > in.length || padLength <= 0) {
            throw new BadPaddingException();
        }
        int i = padLength;
        while (i > 1) {
            try {
                if (in[in.length - i] != 0) {
                    throw new BadPaddingException();
                }
                i--;
            } catch (BadPaddingException ex) {
                if (i == in[in.length - 1] + 1) {
                    /*
                     * RFC2409 states: "All padding bytes, except for the last
                     * one, contain 0x00. The last byte of the padding contains
                     * the number of the padding bytes used, excluding the last
                     * one."
                     * 
                     * Huawei instead counts the last byte also, leading to an
                     * invalid padding. Since Huawei is the only known
                     * implementation of RevPKE, we allow this false padding.
                     */
                    padLength = --i;
                } else {
                    throw ex;
                }
            }
        }
        return Arrays.copyOf(in, in.length - padLength);
    }

    @Override
    public void encrypt() throws GeneralSecurityException {
        cipher.init(Cipher.ENCRYPT_MODE, this.ke, this.IV);
        this.encryptedBody = cipher.doFinal(addRFC2409Padding(this.getBody()));
        this.nextIV = Arrays.copyOfRange(this.encryptedBody, this.encryptedBody.length - cipher.getBlockSize(), this.encryptedBody.length);
        this.isInSync = true;
    }

    @Override
    public void decrypt() throws GeneralSecurityException, GenericIKEParsingException {
        cipher.init(Cipher.DECRYPT_MODE, this.ke, this.IV);
        byte[] plaintext = removeRFC2409Padding(cipher.doFinal(this.encryptedBody));
        this.setBody(plaintext);
        this.nextIV = Arrays.copyOfRange(this.encryptedBody, this.encryptedBody.length - cipher.getBlockSize(), this.encryptedBody.length);
        this.isInSync = true;
    }

    public static <T extends ISAKMPPayload> SymmetricallyEncryptedISAKMPPayload fromStream(Class<T> payloadType, ByteArrayInputStream bais, IKEv1Ciphersuite ciphersuite, SecretKeySpec ke, byte[] iv) throws GenericIKEParsingException {
        try {
            T payload = payloadType.getConstructor((Class<?>[]) null).newInstance((Object[]) null);
            SymmetricallyEncryptedISAKMPPayload encPayload = new SymmetricallyEncryptedISAKMPPayload(payload, ciphersuite, ke, iv);
            int length = encPayload.fillGenericPayloadHeaderFromStream(bais);
            byte[] buffer = new byte[length - GENERIC_PAYLOAD_HEADER_LEN];
            bais.read(buffer);
            encPayload.encryptedBody = buffer;
            encPayload.decrypt();
            return encPayload;
        } catch (ReflectiveOperationException | SecurityException | IOException | GeneralSecurityException ex) {
            throw new ISAKMPParsingException(ex);
        }
    }

    @Override
    public byte[] getCiphertext() {
        if (!isInSync) {
            try {
                this.encrypt();
            } catch (GeneralSecurityException ex) {
                throw new RuntimeException(ex);
            }
        }
        return encryptedBody.clone();
    }

    public byte[] getNextIV() {
        return nextIV.clone();
    }

    @Override
    public boolean isInSync() {
        return isInSync;
    }

    @Override
    public int getLength() {
        return GENERIC_PAYLOAD_HEADER_LEN + this.getCiphertext().length;
    }

    @Override
    public ISAKMPPayload getUnderlyingPayload() {
        return this.underlyingPayload;
    }

    @Override
    public int fillGenericPayloadHeaderFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        return this.underlyingPayload.fillGenericPayloadHeaderFromStream(bais);
    }

    @Override
    public void setNextPayload(IKEPayloadTypeEnum nextPayload) {
        this.underlyingPayload.setNextPayload(nextPayload);
    }

    @Override
    public IKEPayloadTypeEnum getNextPayload() {
        return this.underlyingPayload.getNextPayload();
    }

    @Override
    public IKEPayloadTypeEnum getType() {
        return this.underlyingPayload.getType();
    }

    @Override
    public byte[] getBody() {
        return this.underlyingPayload.getBody();
    }

    @Override
    protected void setBody(byte[] body) throws GenericIKEParsingException {
        this.underlyingPayload.setBody(body);
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        this.underlyingPayload.fillFromStream(bais);
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        if (!isInSync) {
            try {
                this.encrypt();
            } catch (GeneralSecurityException ex) {
                throw new RuntimeException(ex);
            }
        }
        super.writeBytes(baos);
        baos.write(encryptedBody, 0, encryptedBody.length);
    }

    @Override
    public String toString() {
        return "(" + this.underlyingPayload.toString() + ")";
    }
}
