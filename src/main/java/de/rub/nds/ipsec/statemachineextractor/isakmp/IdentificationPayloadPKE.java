/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import static de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload.ID_HEADER_LEN;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IdentificationPayloadPKE extends IdentificationPayload {

    private boolean isEncrypted = false;
    private byte[] encryptedBody = new byte[0];

    public void setEncryptedBody(byte[] encryptedBody) {
        this.encryptedBody = encryptedBody.clone();
        isEncrypted = true;
    }

    public byte[] getEncryptedBody() {
        return encryptedBody.clone();
    }

    @Override
    public void setIdentificationData(byte[] identificationData) {
        super.setIdentificationData(identificationData);
        this.isEncrypted = false;
    }

    @Override
    public void setPort(byte[] port) {
        super.setPort(port);
        this.isEncrypted = false;
    }

    @Override
    public void setProtocolID(byte protocolID) {
        super.setProtocolID(protocolID);
        this.isEncrypted = false;
    }

    @Override
    public void setIdType(IDTypeEnum idType) {
        super.setIdType(idType);
        this.isEncrypted = false;
    }

    @Override
    public int getLength() {
        return ISAKMP_PAYLOAD_HEADER_LEN + encryptedBody.length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        if (!isEncrypted) {
            throw new IllegalStateException("Identification Payload has not been encrypted yet!");
        }
        baos.write(getGenericPayloadHeader(), 0, ISAKMP_PAYLOAD_HEADER_LEN);
        baos.write(encryptedBody, 0, encryptedBody.length);
    }

    @Override
    public byte[] getBody() {
        if (isEncrypted) {
            throw new IllegalStateException("Identification Payload has not been decrypted yet!");
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        super.writeBytes(baos);
        byte[] bytes = baos.toByteArray();
        byte[] result = new byte[bytes.length - ISAKMP_PAYLOAD_HEADER_LEN];
        System.arraycopy(bytes, ISAKMP_PAYLOAD_HEADER_LEN, result, 0, result.length);
        return result;
    }

    public void setPropertiesFromPlaintext(byte[] input) throws ISAKMPParsingException {
        if (input.length < 6) {
            throw new ISAKMPParsingException("Not enough data supplied to build an IdentificationPayload!");
        }
        this.setIdType(IDTypeEnum.get(input[0]));
        this.setProtocolID(input[1]);
        this.setPort(Arrays.copyOfRange(input, 2, 4));
        this.setIdentificationData(Arrays.copyOfRange(input, 4, input.length));
        this.isEncrypted = false;
        encryptedBody = new byte[0];
    }

    public static IdentificationPayloadPKE fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        IdentificationPayloadPKE identificationPayload = new IdentificationPayloadPKE();
        int length = identificationPayload.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = new byte[length - ISAKMP_PAYLOAD_HEADER_LEN];
        int readBytes;
        try {
            readBytes = bais.read(buffer);
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        if (readBytes != length - ISAKMP_PAYLOAD_HEADER_LEN) {
            throw new ISAKMPParsingException("Input stream ended early after " + readBytes + " bytes (should read " + (length - ID_HEADER_LEN) + "bytes)!");
        }
        identificationPayload.setEncryptedBody(buffer);
        identificationPayload.isEncrypted = true;
        return identificationPayload;
    }
}
