/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.IKEv1Ciphersuite;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class to fix Huawei's misunderstanding of RFC2409.
 * 
 * RFC2409 says that the entire body of a payload has to be encrypted.
 * However, for identification payloads, Huawei leaves the 4 bytes (ID type, 
 * Protocol ID, and Port) after the generic ISAKMP header unencrypted.
 * This class generates identification payloads that Huawei understands.
 * 
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SymmetricallyEncryptedIdentificationPayloadHuaweiStyle extends SymmetricallyEncryptedISAKMPPayload {

    private final IdentificationPayload underlyingPayload;

    public SymmetricallyEncryptedIdentificationPayloadHuaweiStyle(IdentificationPayload payload, IKEv1Ciphersuite ciphersuite, SecretKeySpec ke) throws GeneralSecurityException {
        this(payload, ciphersuite, ke, null);
    }

    public SymmetricallyEncryptedIdentificationPayloadHuaweiStyle(IdentificationPayload payload, IKEv1Ciphersuite ciphersuite, SecretKeySpec ke, byte[] iv) throws GeneralSecurityException {
        super(payload, ciphersuite, ke, iv);
        this.underlyingPayload = payload;
    }

    @Override
    public byte[] getBody() {
        return this.underlyingPayload.getIdentificationData();
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        this.underlyingPayload.setIdentificationData(body);
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
        baos.write(getGenericPayloadHeader(), 0, ISAKMP_PAYLOAD_HEADER_LEN);
        baos.write(underlyingPayload.getIdType().getValue());
        baos.write(underlyingPayload.getProtocolID());
        baos.write(underlyingPayload.getPort(), 0, 2);
        baos.write(encryptedBody, 0, encryptedBody.length);
    }

    public static SymmetricallyEncryptedIdentificationPayloadHuaweiStyle fromStream(ByteArrayInputStream bais, IKEv1Ciphersuite ciphersuite, SecretKeySpec ke, byte[] iv) throws ISAKMPParsingException {
        try {
            SymmetricallyEncryptedIdentificationPayloadHuaweiStyle encPayload = new SymmetricallyEncryptedIdentificationPayloadHuaweiStyle(new IdentificationPayload(), ciphersuite, ke, iv);
            int length = encPayload.fillGenericPayloadHeaderFromStream(bais);
            byte[] buffer = new byte[length - ISAKMP_PAYLOAD_HEADER_LEN];
            bais.read(buffer);
            encPayload.underlyingPayload.setBody(buffer);
            encPayload.encryptedBody = Arrays.copyOfRange(buffer, IdentificationPayload.ID_HEADER_LEN - ISAKMP_PAYLOAD_HEADER_LEN, buffer.length);
            encPayload.decrypt();
            return encPayload;
        } catch (IOException | GeneralSecurityException ex) {
            throw new ISAKMPParsingException(ex);
        }
    }

    @Override
    public int getLength() {
        return super.getLength() + IdentificationPayload.ID_HEADER_LEN - ISAKMP_PAYLOAD_HEADER_LEN; // That's a +4 with context
    }

}
