/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.AuthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.CipherAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DHGroupAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.DurationAttribute;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.HashAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.KeyLengthAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.LifeTypeAttributeEnum;
import de.rub.nds.ipsec.statemachineextractor.isakmp.ProposalPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.SecurityAssociationPayload;
import de.rub.nds.ipsec.statemachineextractor.isakmp.TransformPayload;

/**
 *
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public class SecurityAssociationPayloadFactory {

    private SecurityAssociationPayloadFactory() {
    }

    public static SecurityAssociationPayload create(AuthAttributeEnum authMethod, CipherAttributeEnum cipher, KeyLengthAttributeEnum keylength, HashAttributeEnum hash, DHGroupAttributeEnum group, LifeTypeAttributeEnum lifetype, DurationAttribute duration) {
        TransformPayload transformPayload = new TransformPayload();
        transformPayload.setTransformNumber((byte) 1);
        transformPayload.addIKEAttribute(cipher);
        if(!cipher.isIsFixedKeySize()) {
            transformPayload.addIKEAttribute(keylength);
        }
        transformPayload.addIKEAttribute(hash);
        transformPayload.addIKEAttribute(group);
        transformPayload.addIKEAttribute(authMethod);
        transformPayload.addIKEAttribute(lifetype);
        transformPayload.addIKEAttribute(duration);
        ProposalPayload proposalPayload = new ProposalPayload();
        proposalPayload.addTransform(transformPayload);
        SecurityAssociationPayload securityAssociationPayload = new SecurityAssociationPayload();
        securityAssociationPayload.setIdentityOnlyFlag(true);
        securityAssociationPayload.addProposalPayload(proposalPayload);
        return securityAssociationPayload;
    }
    
    public static final SecurityAssociationPayload PSK_DES_MD5_G1     = create(AuthAttributeEnum.PSK, CipherAttributeEnum.DES_CBC, null, HashAttributeEnum.MD5, DHGroupAttributeEnum.GROUP1, LifeTypeAttributeEnum.SECONDS, DurationAttribute.get(28800));
    public static final SecurityAssociationPayload PSK_AES128_SHA1_G5 = create(AuthAttributeEnum.PSK, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP5, LifeTypeAttributeEnum.SECONDS, DurationAttribute.get(28800));
    public static final SecurityAssociationPayload PKE_AES128_SHA1_G5 = create(AuthAttributeEnum.PKE, CipherAttributeEnum.AES_CBC, KeyLengthAttributeEnum.L128, HashAttributeEnum.SHA1, DHGroupAttributeEnum.GROUP5, LifeTypeAttributeEnum.SECONDS, DurationAttribute.get(28800));
}
