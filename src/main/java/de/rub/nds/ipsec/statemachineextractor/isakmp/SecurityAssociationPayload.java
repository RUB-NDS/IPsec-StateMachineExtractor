/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.isakmp;

import de.rub.nds.ipsec.statemachineextractor.util.DatatypeHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SecurityAssociationPayload extends ISAKMPPayload {

    protected static final int SA_HEADER_LEN = 12;

    private int domainOfInterpretation = 0x01; //IPSEC
    private final BitSet situation = new BitSet(3);
    private final List<ProposalPayload> proposals = new ArrayList<>();

    public SecurityAssociationPayload() {
        super(PayloadTypeEnum.SecurityAssociation);
    }

    public int getDomainOfInterpretation() {
        return domainOfInterpretation;
    }

    public void setDomainOfInterpretation(int domainOfInterpretation) {
        this.domainOfInterpretation = domainOfInterpretation;
    }

    public byte[] getSituation() {
        byte[] result = new byte[]{0x00, 0x00, 0x00, 0x00};
        byte[] bytes = this.situation.toByteArray();
        if (bytes.length == 0) {
            return result;
        }
        if (bytes.length > 1 || bytes[0] > 0x07) {
            throw new IllegalStateException("Too many bits in situation");
        }
        result[3] = bytes[0];
        return result;
    }

    public void setIdentityOnlyFlag(boolean value) {
        this.situation.set(0, value);
    }

    public void setSecrecyFlag(boolean value) {
        this.situation.set(1, value);
    }

    public void setIntegrityFlag(boolean value) {
        this.situation.set(2, value);
    }

    public void addProposalPayload(ProposalPayload payload) {
        proposals.add(payload);
    }

    public List<ProposalPayload> getProposalPayloads() {
        return Collections.unmodifiableList(proposals);
    }

    @Override
    public String toString() {
        return "SA";
    }

    @Override
    public int getLength() {
        int length = SA_HEADER_LEN;
        for (ProposalPayload payload : proposals) {
            length += payload.getLength();
        }
        return length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(DatatypeHelper.intTo4ByteArray(domainOfInterpretation), 0, 4);
        baos.write(getSituation(), 0, 4);
        for (int i = 0; i < proposals.size(); i++) {
            ProposalPayload proposal = proposals.get(i);
            if (proposal.getProposalNumber() == -128) {
                proposal.setProposalNumber((byte) i);
            }
            if (i + 1 < proposals.size()) {
                proposal.setNextPayload(PayloadTypeEnum.Proposal);
            }
            proposal.writeBytes(baos);
        }
    }

    public static SecurityAssociationPayload fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        SecurityAssociationPayload securityAssociationPayload = new SecurityAssociationPayload();
        securityAssociationPayload.fillFromStream(bais);
        return securityAssociationPayload;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        this.setDomainOfInterpretation(ByteBuffer.wrap(read4ByteFromStream(bais)).getInt());
        byte[] buffer = read4ByteFromStream(bais);
        this.setIdentityOnlyFlag((buffer[3] & 1) > 0);
        this.setSecrecyFlag((buffer[3] & 2) > 0);
        this.setIntegrityFlag((buffer[3] & 4) > 0);
        this.addProposalPayload(ProposalPayload.fromStream(bais));
        if (length != this.getLength()) {
            throw new ISAKMPParsingException("Payload lengths differ - Computed: " + this.getLength() + " bytes vs. Received: " + length + " bytes!");
        }
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
