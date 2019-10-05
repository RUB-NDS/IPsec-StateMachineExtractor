/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
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
public class ISAKMPPayloadWithPKCS1EncryptedBody extends ISAKMPPayload implements EncryptedISAKMPData {

    private final PrivateKey myPrivateKey;
    private final PublicKey peerPublicKey;
    protected boolean isInSync;
    protected byte[] encryptedBody = new byte[0];
    private final ISAKMPPayload underlyingPayload;

    public ISAKMPPayloadWithPKCS1EncryptedBody(ISAKMPPayload payload, PrivateKey myPrivateKey, PublicKey peerPublicKey) {
        super(payload.getType());
        this.underlyingPayload = payload;
        if (!(myPrivateKey instanceof RSAPrivateKey && peerPublicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("PKCS#1 v1.5 encryption in IPsec only works with RSA!");
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

    public static <T extends ISAKMPPayload> ISAKMPPayloadWithPKCS1EncryptedBody fromStream(Class<T> payloadType, ByteArrayInputStream bais, PrivateKey myPrivateKey, PublicKey peerPublicKey) throws ISAKMPParsingException {
        try {
            T payload = payloadType.getConstructor((Class<?>[]) null).newInstance((Object[]) null);
            ISAKMPPayloadWithPKCS1EncryptedBody encPayload = new ISAKMPPayloadWithPKCS1EncryptedBody(payload, myPrivateKey, peerPublicKey);
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
            throw new IllegalStateException("Ciphertext not up to date. Run encrypt() first!");
        }
        return encryptedBody.clone();
    }

    @Override
    public boolean isIsInSync() {
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
    protected byte[] getGenericPayloadHeader() {
        return super.getGenericPayloadHeader();
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
            throw new IllegalStateException("Encrypted body not up to date. Run encrypt() first!");
        }
        super.writeBytes(baos);
        baos.write(encryptedBody, 0, encryptedBody.length);
    }

}