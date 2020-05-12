/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp.v2;

import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ProposalPayloadv2 extends ISAKMPPayload {

    protected static final int PROPOSAL_PAYLOAD_HEADER_LEN = 8;

    private byte proposalNumber = -128;
    private ProtocolIDEnum protocolId = ProtocolIDEnum.ISAKMP;
    private byte[] SPI = new byte[0];
    private final List<TransformPayloadv2> transforms = new ArrayList<>();

    public ProposalPayloadv2() {
        super(PayloadTypeEnum.Proposal);
    }

    /**
     * @return the length of the full payload, including the generic payload
     * header
     */
    @Override
    public int getLength() {
        int length = PROPOSAL_PAYLOAD_HEADER_LEN;
        length += SPI.length;
        for (TransformPayloadv2 transform : transforms) {
            length += transform.getLength();
        }
        return length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(proposalNumber);
        baos.write(protocolId.getValue());
        baos.write((byte) SPI.length);
        baos.write((byte) transforms.size());
        baos.write(SPI, 0, SPI.length);
        for (int i = 0; i < transforms.size(); i++) {
            TransformPayloadv2 transform = transforms.get(i);
            if (i + 1 < transforms.size()) {
                transform.setNextPayload(PayloadTypeEnum.Transform);
            }
            transform.writeBytes(baos);
        }
    }

    public byte getProposalNumber() {
        return proposalNumber;
    }

    public void setProposalNumber(byte proposalNumber) {
        this.proposalNumber = proposalNumber;
    }

    public ProtocolIDEnum getProtocolId() {
        return protocolId;
    }

    public void setProtocolId(ProtocolIDEnum protocolId) {
        this.protocolId = protocolId;
    }

    public byte[] getSPI() {
        return SPI.clone();
    }

    public void setSPI(byte[] SPI) {
        this.SPI = SPI;
    }

    public byte[] setSPIRandom() {
        this.SPI = new byte[4];
        Random rng = new Random();
        rng.nextBytes(this.SPI);
        return getSPI();
    }

    public void addTransform(TransformPayloadv2 transform) {
        transforms.add(transform);
    }

    public List<TransformPayloadv2> getTransformPayloads() {
        return Collections.unmodifiableList(transforms);
    }

    public static ProposalPayloadv2 fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        ProposalPayloadv2 proposalPayloadv2 = new ProposalPayloadv2();
        proposalPayloadv2.fillFromStream(bais);
        return proposalPayloadv2;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = read4ByteFromStream(bais);
        this.setProposalNumber(buffer[0]);
        this.setProtocolId(ProtocolIDEnum.get(buffer[1]));
        byte spiSize = buffer[2];
        byte nrTransforms = buffer[3];
        this.SPI = new byte[spiSize];
        try {
            int read = bais.read(this.SPI);
            if (read != spiSize) {
                throw new ISAKMPParsingException("Reading from InputStream failed!");
            }
        } catch (IOException ex) {
            throw new ISAKMPParsingException(ex);
        }
        for (byte i = 0; i < nrTransforms; i++) {
            this.addTransform(TransformPayloadv2.fromStream(bais, this.getProtocolId()));
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
