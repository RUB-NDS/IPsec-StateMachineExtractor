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
import de.rub.nds.ipsec.statemachineextractor.isakmp.PayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ISAKMPParsingException;
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
public class SecurityAssociationPayloadv2 extends ISAKMPPayload {

    protected final static int SA_HEADER_LEN = 4;

    private final List<ProposalPayloadv2> proposals = new ArrayList<>();

    public SecurityAssociationPayloadv2() {
        super(PayloadTypeEnum.SecurityAssociation);
    }

    public void addProposalPayloadv2(ProposalPayloadv2 payload) {
        proposals.add(payload);
    }

    public List<ProposalPayloadv2> getProposalPayloads() {
        return Collections.unmodifiableList(proposals);
    }

    @Override
    public String toString() {
        return "SA";
    }

    @Override
    public int getLength() {
        int length = SA_HEADER_LEN;
        for (ProposalPayloadv2 payload : proposals) {
            length += payload.getLength();
        }
        return length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        for (int i = 0; i < proposals.size(); i++) {
            ProposalPayloadv2 proposal = proposals.get(i);
            if (proposal.getProposalNumber() == -128) {
                proposal.setProposalNumber((byte) i);
            }
            if (i + 1 < proposals.size()) {
                proposal.setNextPayload(PayloadTypeEnum.Proposal);
            }
            proposal.writeBytes(baos);
        }
    }

    public static SecurityAssociationPayloadv2 fromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        SecurityAssociationPayloadv2 securityAssociationPayloadv2 = new SecurityAssociationPayloadv2();
        securityAssociationPayloadv2.fillFromStream(bais);
        return securityAssociationPayloadv2;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws ISAKMPParsingException {
        int length = this.fillGenericPayloadHeaderFromStream(bais);
        this.addProposalPayloadv2(ProposalPayloadv2.fromStream(bais));
        if (length != this.getLength()) {
            throw new ISAKMPParsingException("Payload lengths differ - Computed: " + this.getLength() + " bytes vs. Received: " + length + " bytes!");
        }
    }

    @Override
    protected void setBody(byte[] body) throws ISAKMPParsingException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
