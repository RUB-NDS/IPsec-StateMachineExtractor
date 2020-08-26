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
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPPayload;
import de.rub.nds.ipsec.statemachineextractor.ike.IKEPayloadTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.isakmp.ISAKMPParsingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SecurityAssociationPayloadv2 extends IKEv2Payload {

    protected final static int SA_HEADER_LEN = 4;

    private final List<ProposalPayloadv2> proposals = new ArrayList<>();

    public SecurityAssociationPayloadv2() {
        super(IKEPayloadTypeEnum.SecurityAssociationv2);
    }

    public void addProposalPayloadv2(ProposalPayloadv2 payload) {
        proposals.add(payload);
    }

    public List<ProposalPayloadv2> getProposalPayloads() {
        return Collections.unmodifiableList(proposals);
    }

    @Override
    public String toString() {
        return "SAv2";
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
                proposal.setProposalNumber((byte) i); //set 0 but should be 1
            }
            if (i + 1 < proposals.size()) {
                proposal.setNextPayload(IKEPayloadTypeEnum.Proposal);
            }
            proposal.writeBytes(baos);
        }
    }

    public static SecurityAssociationPayloadv2 fromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
        SecurityAssociationPayloadv2 securityAssociationPayloadv2 = new SecurityAssociationPayloadv2();
        securityAssociationPayloadv2.fillFromStream(bais);
        return securityAssociationPayloadv2;
    }

    @Override
    protected void fillFromStream(ByteArrayInputStream bais) throws GenericIKEParsingException {
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
