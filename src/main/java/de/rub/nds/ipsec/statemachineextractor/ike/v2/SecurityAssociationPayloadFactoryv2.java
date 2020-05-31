/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v2;

import de.rub.nds.ipsec.statemachineextractor.ipsec.ProtocolTransformIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.TransformTypeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v2.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.ProposalPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProtocolIDEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.SecurityAssociationPayloadv2;
import de.rub.nds.ipsec.statemachineextractor.isakmp.v2.TransformPayloadv2;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SecurityAssociationPayloadFactoryv2 {

    private SecurityAssociationPayloadFactoryv2() {
    }

    public static SecurityAssociationPayloadv2 createP1SA(ProtocolTransformIDEnum transformIDENC, ProtocolTransformIDEnum transformIDPRF, ProtocolTransformIDEnum transformIDINTEG, ProtocolTransformIDEnum transformIDDH, KeyLengthAttributeEnum keylength) {
        TransformPayloadv2 transformPayloadENC = new TransformPayloadv2();
        transformPayloadENC.setTransformType(TransformTypeEnum.ENCR);
        transformPayloadENC.setTransformId(transformIDENC);
        transformPayloadENC.addAttribute(keylength);
        
        TransformPayloadv2 transformPayloadPRF = new TransformPayloadv2();
        transformPayloadPRF.setTransformType(TransformTypeEnum.PRF);
        transformPayloadPRF.setTransformId(transformIDPRF);
        
        TransformPayloadv2 transformPayloadINTEG = new TransformPayloadv2();
        transformPayloadINTEG.setTransformType(TransformTypeEnum.INTEG);
        transformPayloadINTEG.setTransformId(transformIDINTEG);
        
        TransformPayloadv2 transformPayloadDH = new TransformPayloadv2();
        transformPayloadDH.setTransformType(TransformTypeEnum.DH);
        transformPayloadDH.setTransformId(transformIDDH);
        
        ProposalPayloadv2 proposalPayload = new ProposalPayloadv2();
        proposalPayload.addTransform(transformPayloadENC);
        proposalPayload.addTransform(transformPayloadPRF);
        proposalPayload.addTransform(transformPayloadINTEG);
        proposalPayload.addTransform(transformPayloadDH);

        SecurityAssociationPayloadv2 securityAssociationPayload = new SecurityAssociationPayloadv2();
        securityAssociationPayload.addProposalPayloadv2(proposalPayload);
        return securityAssociationPayload;
    }
}
