/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class ProposalPayload extends ISAKMPPayload {

    protected static final int PROPOSAL_PAYLOAD_HEADER_LEN = 8;

    private byte proposalNumber = 1;
    private byte protocolId = 1; //ISAKMP
    private byte[] SPI = new byte[0];
    private final List<TransformPayload> transforms = new ArrayList<>();

    public ProposalPayload() {
        super(PayloadTypeEnum.Proposal);
    }

    /**
     * @return the length of the full payload, including the generic payload
     * header
     */
    @Override
    public int getLength() {
        int length = PROPOSAL_PAYLOAD_HEADER_LEN;
        for (TransformPayload transform : transforms) {
            length += transform.getLength();
        }
        return length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(proposalNumber);
        baos.write(protocolId);
        baos.write((byte) SPI.length);
        baos.write((byte) transforms.size());
        for (TransformPayload transform : transforms) {
            transform.writeBytes(baos);
        }
    }

    public byte getProposalNumber() {
        return proposalNumber;
    }

    public void setProposalNumber(byte proposalNumber) {
        this.proposalNumber = proposalNumber;
    }

    public byte getProtocolId() {
        return protocolId;
    }

    public void setProtocolId(byte protocolId) {
        this.protocolId = protocolId;
    }

    public byte[] getSPI() {
        return SPI.clone();
    }

    public void setSPI(byte[] SPI) {
        this.SPI = SPI;
    }

    public void addTransform(TransformPayload transform) {
        transforms.add(transform);
    }
    
    public List<TransformPayload> getTransformPayloads() {
        return Collections.unmodifiableList(transforms);
    }

    public static ProposalPayload fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        ProposalPayload proposalPayload = new ProposalPayload();
        proposalPayload.fillFromStream(bais);
        return proposalPayload;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        byte[] buffer = read4ByteFromStream(bais);
        this.setProposalNumber(buffer[0]);
        this.setProtocolId(buffer[1]);
        if (buffer[2] != 0) {
            throw new ISAKMPParsingException("SPI Size is not zero!");
        }
        for(byte i = 0; i < buffer[3]; i++) {
            this.addTransform(TransformPayload.fromStream(bais));
        }
        if (length != this.getLength()) {
            throw new ISAKMPParsingException("Payload lengths differ - Computed: " + this.getLength() + " bytes vs. Received: " + length + " bytes!");
        }
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
