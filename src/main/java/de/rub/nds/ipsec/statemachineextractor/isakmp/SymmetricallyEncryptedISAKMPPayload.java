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
import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SymmetricallyEncryptedISAKMPPayload extends EncryptedISAKMPPayload {

    private final SecretKey secretKey;
    private IvParameterSpec IV;
    private byte[] nextIV = new byte[0];
    private final Cipher cipher;
    
    public SymmetricallyEncryptedISAKMPPayload(ISAKMPPayload payload, SecretKey secretKey, CipherAttributeEnum mode, byte[] IV) throws GeneralSecurityException {
        this(payload, secretKey, Cipher.getInstance(mode.cipherJCEName() + '/' + mode.modeOfOperationJCEName() + "/NoPadding"));
        this.IV = new IvParameterSpec(IV);
    }
    
    public SymmetricallyEncryptedISAKMPPayload(ISAKMPPayload payload, SecretKey secretKey, CipherAttributeEnum mode) throws GeneralSecurityException {
        this(payload, secretKey, Cipher.getInstance(mode.cipherJCEName() + '/' + mode.modeOfOperationJCEName() + "/NoPadding"));
        this.IV = new IvParameterSpec(new byte[mode.getBlockSize()]);
    }
    
    private SymmetricallyEncryptedISAKMPPayload(ISAKMPPayload payload, SecretKey secretKey, Cipher cipher) throws GeneralSecurityException {
        super(payload);
        this.secretKey = secretKey;
        this.isInSync = false;
        this.cipher = cipher;
    }

    @Override
    public void encrypt() throws GeneralSecurityException {
        byte[] padded = addRFC2409Padding(this.getBody());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IV);
        this.encryptedBody = cipher.doFinal(padded);
        this.isInSync = true;
    }

    @Override
    public void decrypt() throws GeneralSecurityException, ISAKMPParsingException {
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IV);
        byte[] plaintext = removeRFC2409Padding(cipher.doFinal(encryptedBody));
        this.setBody(plaintext);
        this.nextIV = new byte[cipher.getBlockSize()];
        System.arraycopy(encryptedBody, encryptedBody.length - cipher.getBlockSize(), this.nextIV, 0, cipher.getBlockSize());
        this.isInSync = true;
    }
    
    byte[] addRFC2409Padding(byte[] in) {
        int byteLength = ((int) Math.ceil((float) in.length / cipher.getBlockSize())) * cipher.getBlockSize();
        if (in.length % cipher.getBlockSize() == 0) {
            byteLength += cipher.getBlockSize();
        }
        byte[] out = new byte[byteLength];
        System.arraycopy(in, 0, out, 0, in.length);
        out[out.length - 1] = (byte)(out.length - in.length - 1);
        return out;
    }
    
    byte[] removeRFC2409Padding(byte[] in) throws BadPaddingException, IllegalBlockSizeException {
        if (in.length % cipher.getBlockSize() != 0) {
            throw new IllegalBlockSizeException();
        }
        int padLength = in[in.length - 1] + 1;
        if (padLength > cipher.getBlockSize() || padLength <= 0) {
            throw new BadPaddingException();
        }
        int i = padLength;
        while(i > 1) {
            if(in[in.length - i] != 0) {
                throw new BadPaddingException();
            }
            i--;
        }
        byte[] out = new byte[in.length - padLength];
        System.arraycopy(in, 0, out, 0, in.length - padLength);
        return out;
    }

    public byte[] getNextIV() {
        return nextIV.clone();
    }

    public static <T extends ISAKMPPayload> SymmetricallyEncryptedISAKMPPayload fromStream(Class<T> payloadType, ByteArrayInputStream bais, SecretKey secretKey, CipherAttributeEnum mode, byte[] IV) throws ISAKMPParsingException {
        try {
            T payload = payloadType.getConstructor((Class<?>[]) null).newInstance((Object[]) null);
            SymmetricallyEncryptedISAKMPPayload encPayload = new SymmetricallyEncryptedISAKMPPayload(payload, secretKey, mode, IV);
            int length = encPayload.fillGenericPayloadHeaderFromStream(bais);
            byte[] buffer = new byte[length - ISAKMP_PAYLOAD_HEADER_LEN];
            bais.read(buffer);
            encPayload.encryptedBody = buffer;
            encPayload.decrypt();
            return encPayload;
        } catch (ReflectiveOperationException | SecurityException | IOException | GeneralSecurityException ex) {
            throw new ISAKMPParsingException(ex);
        }
    }
}
