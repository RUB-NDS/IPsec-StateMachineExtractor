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
import de.rub.nds.ipsec.statemachineextractor.ike.IDTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.IKEv2ParsingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public abstract class IdentificationPayload extends IKEv2Payload {

    protected static final int ID_HEADER_LEN = 8;
    protected static final int RESERVED_LEN = 3;
    private IDTypeEnum idType = IDTypeEnum.RESERVED;
    private byte[] identificationData = new byte[0];
    private byte[] IDx;

    public IdentificationPayload(IKEPayloadTypeEnum type) {
        super(type);
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

    protected void setIDx() {
        IDx = new byte[identificationData.length + RESERVED_LEN + 1];
        IDx[0] = idType.getValue();
        System.arraycopy(identificationData, 0, IDx, RESERVED_LEN + 1, identificationData.length);
    }

    protected byte[] getIDx() {
        return IDx.clone();
    }

    @Override
    public int getLength() {
        return ID_HEADER_LEN + identificationData.length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(idType.getValue());
        baos.write(new byte[RESERVED_LEN], 0, RESERVED_LEN);
        baos.write(identificationData, 0, identificationData.length);
    }

    @Override
    protected void setBody(byte[] body) throws IKEv2ParsingException {
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
            throw new IKEv2ParsingException(ex);
        }
        if (readBytes < length - GENERIC_PAYLOAD_HEADER_LEN) {
            throw new IKEv2ParsingException("Input stream ended early after " + readBytes + " bytes (should read " + (length - GENERIC_PAYLOAD_HEADER_LEN) + "bytes)!");
        }
        this.setBody(buffer);
        setIDx();
    }
}
