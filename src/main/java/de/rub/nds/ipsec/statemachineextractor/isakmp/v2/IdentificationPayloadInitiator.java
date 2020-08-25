/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp.v2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.IDTypeEnum;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IdentificationPayloadInitiator extends ISAKMPPayload {

    protected static final int ID_HEADER_LEN = 8;

    private IDTypeEnum idType = IDTypeEnum.RESERVED;
    private final byte[] reserved = new byte[]{0x00, 0x00, 0x00};
    private byte[] identificationData = new byte[0];
    private byte[] IDi;

    public IdentificationPayloadInitiator() {
        super(PayloadTypeEnum.IdentificationInitiator);
    }

    public IDTypeEnum getIdType() {
        return idType;
    }

    public void setIdType(IDTypeEnum idType) {
        this.idType = idType;
    }

    public byte[] getIdentificationData() {
        return identificationData.clone();
    }

    public void setIdentificationData(byte[] identificationData) {
        this.identificationData = identificationData;
    }

    public void setIDi() {
        IDi = new byte[reserved.length + identificationData.length + 1];
        IDi[0] = idType.getValue();
        System.arraycopy(reserved, 0, IDi, 1, reserved.length);
        System.arraycopy(identificationData, 0, IDi, 4, identificationData.length);
    }

    public byte[] getIDi() {
        return IDi.clone();
    }

    @Override
    public String toString() {
        return "IDInit";
    }

    @Override
    public int getLength() {
        return ID_HEADER_LEN + identificationData.length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(idType.getValue());
        baos.write(reserved, 0, reserved.length);
        baos.write(identificationData, 0, identificationData.length);
    }

    public static IdentificationPayloadInitiator fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        IdentificationPayloadInitiator identificationPayload = new IdentificationPayloadInitiator();
        identificationPayload.fillFromStream(bais);
        return identificationPayload;
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        this.setIdType(IDTypeEnum.get(body[0]));
        this.setIdentificationData(Arrays.copyOfRange(body, 4, body.length));
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = new byte[length - ISAKMP_PAYLOAD_HEADER_LEN];
        int readBytes;
        try {
            readBytes = bais.read(buffer);
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        if (readBytes < length - ISAKMP_PAYLOAD_HEADER_LEN) {
            throw new ISAKMPParsingException("Input stream ended early after " + readBytes + " bytes (should read " + (length - ISAKMP_PAYLOAD_HEADER_LEN) + "bytes)!");
        }
        this.setBody(buffer);
        setIDi();
    }

}
