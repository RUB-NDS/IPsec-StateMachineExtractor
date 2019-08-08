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
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class PKCS1EncryptedISAKMPPayload extends EncryptedISAKMPPayload {

    private final KeyPair myKeyPair;
    private final PublicKey peerPublicKey;

    public PKCS1EncryptedISAKMPPayload(ISAKMPPayload payload, KeyPair myKeyPair, PublicKey peerPublicKey) {
        super(payload);
        if(!(myKeyPair.getPrivate() instanceof RSAPrivateKey && myKeyPair.getPublic() instanceof RSAPublicKey && peerPublicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("PKCS#1 v1.5 encryption in IPsec only works with RSA!");
        }
        this.myKeyPair = myKeyPair;
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
        cipher.init(Cipher.DECRYPT_MODE, this.myKeyPair.getPrivate());
        byte[] plaintext = cipher.doFinal(this.encryptedBody);
        this.setBody(plaintext);
        this.isInSync = true;
    }
    
    public static <T extends ISAKMPPayload> PKCS1EncryptedISAKMPPayload fromStream(Class<T> payloadType, ByteArrayInputStream bais, KeyPair myKeyPair, PublicKey peerPublicKey) throws ISAKMPParsingException {
        try {
            T payload = payloadType.getConstructor((Class<?>[]) null).newInstance((Object[]) null);
            PKCS1EncryptedISAKMPPayload encPayload = new PKCS1EncryptedISAKMPPayload(payload, myKeyPair, peerPublicKey);
            int length = encPayload.fillGenericPayloadHeaderFromStream(bais);
            byte[] buffer = new byte[bais.available()];
            bais.read(buffer);
            encPayload.encryptedBody = buffer;
            encPayload.decrypt();
            return encPayload;
        } catch (ReflectiveOperationException | SecurityException | IOException | GeneralSecurityException ex) {
            throw new ISAKMPParsingException(ex);
        }
    }
}
