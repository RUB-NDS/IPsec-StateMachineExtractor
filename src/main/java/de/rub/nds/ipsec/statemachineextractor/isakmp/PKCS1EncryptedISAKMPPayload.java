/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class PKCS1EncryptedISAKMPPayload extends ISAKMPPayload implements EncryptedISAKMPPayload {

    private final PrivateKey myPrivateKey;
    private final PublicKey peerPublicKey;
    protected boolean isInSync;
    protected byte[] encryptedBody = new byte[0];
    private final ISAKMPPayload underlyingPayload;

    public PKCS1EncryptedISAKMPPayload(ISAKMPPayload payload, PrivateKey myPrivateKey, PublicKey peerPublicKey) {
        super(payload.getType());
        this.underlyingPayload = payload;
        if (!(myPrivateKey instanceof RSAPrivateKey && peerPublicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("PKCS#1 v1.5 encryption in IKE only works with RSA!");
        }
        this.myPrivateKey = myPrivateKey;
        this.peerPublicKey = peerPublicKey;
        this.isInSync = false;
    }

    @Override
    public void encrypt() throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.peerPublicKey);
        this.encryptedBody = cipher.doFinal(this.getBody());
        this.isInSync = true;
    }

    @Override
    public void decrypt() throws GeneralSecurityException, ISAKMPParsingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.myPrivateKey);
        byte[] plaintext = cipher.doFinal(this.encryptedBody);
        this.setBody(plaintext);
        this.isInSync = true;
    }

    public static <T extends ISAKMPPayload> PKCS1EncryptedISAKMPPayload fromStream(Class<T> payloadType, ByteArrayInputStream bais, PrivateKey myPrivateKey, PublicKey peerPublicKey) throws ISAKMPParsingException {
        try {
            T payload = payloadType.getConstructor((Class<?>[]) null).newInstance((Object[]) null);
            PKCS1EncryptedISAKMPPayload encPayload = new PKCS1EncryptedISAKMPPayload(payload, myPrivateKey, peerPublicKey);
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

    @Override
    public boolean isInSync() {
        return isInSync;
    }

    @Override
    public int getLength() {
        return ISAKMP_PAYLOAD_HEADER_LEN + this.getCiphertext().length;
    }

    @Override
    public ISAKMPPayload getUnderlyingPayload() {
        return this.underlyingPayload;
    }

    @Override
    protected int fillGenericPayloadHeaderFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        return this.underlyingPayload.fillGenericPayloadHeaderFromStream(bais);
    }

    @Override
    public void setNextPayload(PayloadTypeEnum nextPayload) {
        this.underlyingPayload.setNextPayload(nextPayload);
    }

    @Override
    public PayloadTypeEnum getNextPayload() {
        return this.underlyingPayload.getNextPayload();
    }

    @Override
    public PayloadTypeEnum getType() {
        return this.underlyingPayload.getType();
    }

    @Override
    public byte[] getBody() {
        return this.underlyingPayload.getBody();
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        this.underlyingPayload.setBody(body);
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
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
        return "<" + this.underlyingPayload.toString() + ">";
    }
}
