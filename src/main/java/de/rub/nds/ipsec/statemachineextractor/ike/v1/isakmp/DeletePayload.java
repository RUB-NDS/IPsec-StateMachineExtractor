/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp;

import de.rub.nds.ipsec.statemachineextractor.ike.GenericIKEParsingException;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class DeletePayload extends ISAKMPPayload {

    protected static final int DELETE_HEADER_LEN = 12;

    private int domainOfInterpretation = 0x01; //IPSEC
    private byte protocolID = 0x01; //ISAKMP
    private byte spiSize = 16; //ISAKMP SPI is the cookie pair
    private List<byte[]> spis = new ArrayList<>();

    public DeletePayload() {
        super(IKEPayloadTypeEnum.Delete);
    }

    public int getDomainOfInterpretation() {
        return domainOfInterpretation;
    }

    public void setDomainOfInterpretation(int domainOfInterpretation) {
        this.domainOfInterpretation = domainOfInterpretation;
    }

    public byte getProtocolID() {
        return protocolID;
    }

    public void setProtocolID(byte protocolID) {
        this.protocolID = protocolID;
    }

    public byte getSpiSize() {
        return spiSize;
    }

    public void setSpiSize(byte spiSize) {
        this.spiSize = spiSize;
    }

    public void addSPI(byte[] spi) {
        if (spi.length != this.spiSize) {
            throw new IllegalArgumentException("SPI size is wrong! Got " + spi.length + " bytes, but SPI size is " + this.spiSize + "!");
        }
        spis.add(spi);
    }

    public List<byte[]> getSPIs() {
        return Collections.unmodifiableList(spis);
    }

    @Override
    public String toString() {
        return "DEL";
    }

    @Override
    public int getLength() {
        return DELETE_HEADER_LEN + spis.size() * spiSize;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(DatatypeHelper.intTo4ByteArray(domainOfInterpretation), 0, 4);
        baos.write(protocolID);
        baos.write(spiSize);
        baos.write(DatatypeHelper.intTo4ByteArray(spis.size()), 2, 2);
        spis.forEach((spi) -> {
            baos.write(spi, 0, spi.length);
        });
    }

    public static DeletePayload fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        DeletePayload deletePayload = new DeletePayload();
        deletePayload.fillFromStream(bais);
        return deletePayload;
    }

    protected static byte[] readSPIFromStream(ByteArrayInputStream bais, byte spiSize) throws ISAKMPParsingException {
        byte[] buffer = new byte[spiSize];
        try {
            int read = bais.read(buffer);
            if (read != spiSize) {
                throw new ISAKMPParsingException("Reading from InputStream failed!");
            }
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        return buffer;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        this.setDomainOfInterpretation(ByteBuffer.wrap(read4ByteFromStream(bais)).getInt());
        byte[] buffer = read4ByteFromStream(bais);
        this.setProtocolID(buffer[0]);
        this.setSpiSize(buffer[1]);
        int numberOfSPIs = ((buffer[2] & 0xff) << 8) | (buffer[3] & 0xff);
        for (int i = 0; i < numberOfSPIs; i++) {
            spis.add(readSPIFromStream(bais, spiSize));
        }
        if (length != this.getLength()) {
            throw new ISAKMPParsingException("Payload lengths differ - Computed: " + this.getLength() + " bytes vs. Received: " + length + " bytes!");
        }
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
