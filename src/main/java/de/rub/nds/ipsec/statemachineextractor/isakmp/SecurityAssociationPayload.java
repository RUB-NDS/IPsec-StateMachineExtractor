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
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SecurityAssociationPayload extends ISAKMPPayload {

    protected static final int SA_HEADER_LEN = 12;

    private int domainOfInterpretation = 0x01; //IPSEC
    private final BitSet situation = new BitSet(3);
    private final List<ProposalPayload> payloads = new ArrayList<>();

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
        payloads.add(payload);
    }

    @Override
    public int getLength() {
        int length = SA_HEADER_LEN;
        for (ProposalPayload payload : payloads) {
            length += payload.getLength();
        }
        return length;
    }

    @Override
    public void writeBytes(ByteArrayOutputStream baos) {
        super.writeBytes(baos);
        baos.write(DatatypeHelper.intTo4ByteArray(domainOfInterpretation), 0, 4);
        baos.write(getSituation(), 0, 4);
        for (ProposalPayload payload : payloads) {
            payload.writeBytes(baos);
        }
    }

}
