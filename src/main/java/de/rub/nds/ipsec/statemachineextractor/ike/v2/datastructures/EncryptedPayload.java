/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2.datastructures;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2ParsingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class EncryptedPayload extends IKEv2Payload {

    protected static final int ID_HEADER_LEN = 4;

    private byte[] IV;
    private byte[] padding = new byte[0];
    private byte padLength = 0;
    private byte[] encryptedPayloads;
    private byte[] INTEGChecksumData = new byte[0];

    public EncryptedPayload() {
        super(IKEPayloadTypeEnum.EncryptedAndAuthenticated);
    }

    public byte[] getIV() {
        return IV.clone();
    }

    public void setIV(byte[] IV) {
        this.IV = IV;
    }

    public byte[] getEncryptedPayloads() {
        return encryptedPayloads.clone();
    }

    public void setEncryptedPayloads(byte[] encryptedPayloads) {
        this.encryptedPayloads = encryptedPayloads;
    }

    public byte[] getINTEGChecksumData() {
        return INTEGChecksumData.clone();
    }

    public void setINTEGChecksumData(byte[] INTEGChecksumData) {
        this.INTEGChecksumData = INTEGChecksumData;
    }

    public void setPadLength(byte padLength) {
        this.padLength = padLength;
    }

    public int getPadLengthINT() {
        return (int) padLength;
    }

    public byte getPadLength() {
        return padLength;
    }

    public byte[] getPadding() {
        return padding.clone();
    }

    public void setPadding(byte[] padding) {
        this.padding = padding.clone();
        this.padLength = (byte) this.padding.length;
    }

    public void genRandomPadding() {
        padding = new byte[(int) padLength];
        SecureRandom random = new SecureRandom();
        random.nextBytes(padding);
    }

    @Override
    public String toString() {
        return "ENC_AUTH";
    }

    @Override
    public int getLength() {
        return ID_HEADER_LEN + 16 + encryptedPayloads.length + 12;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(IV, 0, IV.length);
        baos.write(encryptedPayloads, 0, encryptedPayloads.length);
        if (INTEGChecksumData.length > 0) {
            baos.write(INTEGChecksumData, 0, INTEGChecksumData.length);
        }
    }

    public static EncryptedPayload fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        EncryptedPayload encPayload = new EncryptedPayload();
        encPayload.fillFromStream(bais);
        return encPayload;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = new byte[length - GENERIC_PAYLOAD_HEADER_LEN];
        int readBytes;
        try {
            readBytes = bais.read(buffer);
        } catch (IOException ex) {
            throw new IKEv2ParsingException(ex);
        }
        if (readBytes < length - GENERIC_PAYLOAD_HEADER_LEN) {
            throw new IKEv2ParsingException("Input stream ended early after " + readBytes + " bytes (should read " + (length - GENERIC_PAYLOAD_HEADER_LEN) + "bytes)!");
        }
    }

    @Override
    protected void setBody(byte[] body) throws IKEv2ParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
