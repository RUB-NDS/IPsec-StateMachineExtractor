/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2019 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.ike.v1;

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

    public static SecurityAssociationPayload create(IKEv1Attribute.Auth authMethod, IKEv1Attribute.Cipher cipher, IKEv1Attribute.KeyLength keylength, IKEv1Attribute.Hash hash, IKEv1Attribute.DH group, IKEv1Attribute.LifeType lifetype, int duration) {
        TransformPayload transformPayload = new TransformPayload();
        transformPayload.setTransformNumber((byte) 1);
        transformPayload.addIKEAttribute(cipher.getAttribute());
        if (keylength != null && cipher != IKEv1Attribute.Cipher.DES_CBC && cipher != IKEv1Attribute.Cipher.TRIPPLEDES_CBC && cipher != IKEv1Attribute.Cipher.IDEA_CBC) {
            transformPayload.addIKEAttribute(keylength.getAttribute());
        }
        transformPayload.addIKEAttribute(hash.getAttribute());
        transformPayload.addIKEAttribute(group.getAttribute());
        transformPayload.addIKEAttribute(authMethod.getAttribute());
        transformPayload.addIKEAttribute(lifetype.getAttribute());
        transformPayload.addIKEAttribute(IKEv1Attribute.Duration.getAttribute(duration));
        ProposalPayload proposalPayload = new ProposalPayload();
        proposalPayload.addTransform(transformPayload);
        SecurityAssociationPayload securityAssociationPayload = new SecurityAssociationPayload();
        securityAssociationPayload.setIdentityOnlyFlag(true);
        securityAssociationPayload.addProposalPayload(proposalPayload);
        return securityAssociationPayload;
    }
    
    public static final SecurityAssociationPayload PSK_DES_MD5_G1     = create(IKEv1Attribute.Auth.PSK, IKEv1Attribute.Cipher.DES_CBC, null, IKEv1Attribute.Hash.MD5, IKEv1Attribute.DH.GROUP1, IKEv1Attribute.LifeType.SECONDS, 28800);
    public static final SecurityAssociationPayload PSK_AES128_SHA1_G5 = create(IKEv1Attribute.Auth.PSK, IKEv1Attribute.Cipher.AES_CBC, IKEv1Attribute.KeyLength.L128, IKEv1Attribute.Hash.SHA1, IKEv1Attribute.DH.GROUP5, IKEv1Attribute.LifeType.SECONDS, 28800);
    public static final SecurityAssociationPayload PKE_AES128_SHA1_G5 = create(IKEv1Attribute.Auth.PKE, IKEv1Attribute.Cipher.AES_CBC, IKEv1Attribute.KeyLength.L128, IKEv1Attribute.Hash.SHA1, IKEv1Attribute.DH.GROUP5, IKEv1Attribute.LifeType.SECONDS, 28800);
}
