/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.shims;

import de.rub.nds.ipsec.statemachineextractor.Main;
import de.rub.nds.ipsec.statemachineextractor.isakmp.*;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IdentificationPayload;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class CiscoPKEIdentificationPayload extends IdentificationPayload {

    @Override
    public IDTypeEnum getIdType() {
        throw new IllegalStateException("With Cisco PKE, this byte contains a part of the ciphertext. Use getIdentificationData() to get the full ciphertext.");
    }

    @Override
    public void setIdType(IDTypeEnum idType) {
        throw new IllegalStateException("With Cisco PKE, this byte contains a part of the ciphertext. Use setIdentificationData() to set the full ciphertext.");
    }

    @Override
    public byte getProtocolID() {
        throw new IllegalStateException("With Cisco PKE, this byte contains a part of the ciphertext. Use getIdentificationData() to get the full ciphertext.");
    }

    @Override
    public void setProtocolID(byte protocolID) {
        throw new IllegalStateException("With Cisco PKE, this byte contains a part of the ciphertext. Use setIdentificationData() to set the full ciphertext.");
    }

    @Override
    public byte[] getPort() {
        throw new IllegalStateException("With Cisco PKE, this byte contains a part of the ciphertext. Use getIdentificationData() to get the full ciphertext.");
    }

    @Override
    public void setPort(byte[] port) {
        throw new IllegalStateException("With Cisco PKE, this byte contains a part of the ciphertext. Use setIdentificationData() to set the full ciphertext.");
    }

    @Override
    public byte[] getIdentificationData() {
        return super.getIdentificationData();
    }

    @Override
    public void setIdentificationData(byte[] identificationData) {
        super.setIdentificationData(identificationData);
    }

    @Override
    public int getLength() {
        return super.getLength() - 4;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        baos.write(getGenericPayloadHeader(), 0, ISAKMP_PAYLOAD_HEADER_LEN);
        byte[] identificationData = getIdentificationData();
        baos.write(identificationData, 0, identificationData.length);
    }

    public static CiscoPKEIdentificationPayload fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        CiscoPKEIdentificationPayload identificationPayload = new CiscoPKEIdentificationPayload();
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
        identificationPayload.setIdentificationData(buffer);
        return identificationPayload;
    }
}
