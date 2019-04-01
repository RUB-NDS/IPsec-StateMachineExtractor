/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayOutputStream;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class IdentificationPayload extends ISAKMPPayload {

    protected static final int ID_HEADER_LEN = 8;

    private IDTypeEnum idType = IDTypeEnum.RESERVED;
    private byte protocolID = 0x00;
    private byte[] port = new byte[2];
    private byte[] identificationData = new byte[0];

    public IdentificationPayload() {
        super(PayloadTypeEnum.Identification);
    }

    public IDTypeEnum getIdType() {
        return idType;
    }

    public void setIdType(IDTypeEnum idType) {
        this.idType = idType;
    }

    public byte getProtocolID() {
        return protocolID;
    }

    public void setProtocolID(byte protocolID) {
        this.protocolID = protocolID;
    }

    public byte[] getPort() {
        return port.clone();
    }

    public void setPort(byte[] port) {
        if (port.length != 2)
            throw new IllegalArgumentException("Port must be exactly 2 bytes!");
        this.port = port;
    }

    public byte[] getIdentificationData() {
        return identificationData.clone();
    }

    public void setIdentificationData(byte[] identificationData) {
        this.identificationData = identificationData;
    }

    @Override
    public int getLength() {
        return ID_HEADER_LEN + identificationData.length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(idType.getValue());
        baos.write(protocolID);
        baos.write(port, 0, 2);
        baos.write(identificationData, 0, identificationData.length);
    }

}
