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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IDTypeEnum;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IdentificationPayloadResponder extends IKEv2Payload {

    protected static final int ID_HEADER_LEN = 8;

    private IDTypeEnum idType = IDTypeEnum.RESERVED;
    private final byte[] reserved = new byte[]{0x00, 0x00, 0x00};
    private byte[] identificationData = new byte[0];
    private byte[] IDr;

    public IdentificationPayloadResponder() {
        super(IKEPayloadTypeEnum.IdentificationResponder);
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

    public void setIDr() {
        IDr = new byte[reserved.length + identificationData.length + 1];
        IDr[0] = idType.getValue();
        System.arraycopy(reserved, 0, IDr, 1, reserved.length);
        System.arraycopy(identificationData, 0, IDr, 4, identificationData.length);
    }

    public byte[] getIDr() {
        return IDr.clone();
    }

    @Override
    public String toString() {
        return "IDResp";
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

    public static IdentificationPayloadResponder fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        IdentificationPayloadResponder identificationPayload = new IdentificationPayloadResponder();
        identificationPayload.fillFromStream(bais);
        return identificationPayload;
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        this.setIdType(IDTypeEnum.get(body[0]));
        this.setIdentificationData(Arrays.copyOfRange(body, 4, body.length));
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = new byte[length - GENERIC_PAYLOAD_HEADER_LEN];
        int readBytes;
        try {
            readBytes = bais.read(buffer);
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        if (readBytes < length - GENERIC_PAYLOAD_HEADER_LEN) {
            throw new ISAKMPParsingException("Input stream ended early after " + readBytes + " bytes (should read " + (length - GENERIC_PAYLOAD_HEADER_LEN) + "bytes)!");
        }
        this.setBody(buffer);
        setIDr();
    }

}